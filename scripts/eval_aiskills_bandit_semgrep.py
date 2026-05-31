"""ai-skills 204 — Bandit + Semgrep 직접 측정 (Python SAST baseline).

각 archive unpack → Bandit + Semgrep 실행 → finding 수 → verdict 변환.

verdict 정책:
  Bandit  : HIGH severity ≥ 1 → MALICIOUS, MEDIUM ≥ 1 → SUSPICIOUS, else CLEAN
  Semgrep : finding ≥ 1 → MALICIOUS, else CLEAN

ground truth: 모두 malicious (DataDog ai-skills/malicious_intent)
→ catch (MAL/SUS) = TP, miss (CLEAN) = FN

산출:
  results_ai_skills_bandit.json
  results_ai_skills_semgrep.json
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import time
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CACHE = ROOT / "scripts" / "eval_real_data" / "cache" / "ai_skills"
FX = ROOT / "scripts" / "eval_real_data" / "ai_skills_fixtures.json"


def unpack_archive(zip_path: Path, dest: Path):
    """zip+password 'infected' unpack."""
    with zipfile.ZipFile(zip_path, "r") as z:
        z.setpassword(b"infected")
        z.extractall(dest)


def run_bandit(target_dir: Path) -> dict:
    """Bandit Python 정적 분석. issue list 반환."""
    try:
        r = subprocess.run(
            ["bandit", "-r", str(target_dir), "-f", "json", "-q"],
            capture_output=True, text=True, timeout=60,
        )
        # Bandit exit 0 = clean, 1 = issues found, >1 = error
        if r.returncode > 1:
            return {"error": r.stderr[:300]}
        out = json.loads(r.stdout) if r.stdout else {}
        results = out.get("results", [])
        # severity별 카운트
        sev = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for issue in results:
            s = (issue.get("issue_severity") or "").upper()
            if s in sev:
                sev[s] += 1
        # verdict 변환
        if sev["HIGH"] >= 1:
            verdict = "MALICIOUS"
        elif sev["MEDIUM"] >= 1:
            verdict = "SUSPICIOUS"
        elif sev["LOW"] >= 1:
            verdict = "SUSPICIOUS"
        else:
            verdict = "CLEAN"
        return {
            "verdict": verdict,
            "high": sev["HIGH"],
            "medium": sev["MEDIUM"],
            "low": sev["LOW"],
            "total_issues": len(results),
        }
    except subprocess.TimeoutExpired:
        return {"error": "timeout", "verdict": "ERROR"}
    except Exception as e:
        return {"error": str(e), "verdict": "ERROR"}


def run_semgrep(target_dir: Path) -> dict:
    """Semgrep — 명시적 ruleset (auto config 는 metrics off 와 비호환)."""
    try:
        r = subprocess.run(
            ["semgrep", "scan",
             "--config", "p/python",
             "--config", "p/security-audit",
             "--json", "--quiet", "--disable-version-check",
             "--metrics", "off",
             str(target_dir)],
            capture_output=True, text=True, timeout=120,
        )
        if r.returncode > 1 and not r.stdout:
            return {"error": r.stderr[:300], "verdict": "ERROR"}
        out = json.loads(r.stdout) if r.stdout else {}
        findings = out.get("results", [])
        # severity 별
        sev = {"ERROR": 0, "WARNING": 0, "INFO": 0}
        for f in findings:
            s = (f.get("extra", {}).get("severity") or "").upper()
            if s in sev:
                sev[s] += 1
        if sev["ERROR"] >= 1:
            verdict = "MALICIOUS"
        elif sev["WARNING"] >= 1:
            verdict = "SUSPICIOUS"
        elif sev["INFO"] >= 1:
            verdict = "SUSPICIOUS"
        else:
            verdict = "CLEAN"
        return {
            "verdict": verdict,
            "error_sev": sev["ERROR"],
            "warning": sev["WARNING"],
            "info": sev["INFO"],
            "total_findings": len(findings),
        }
    except subprocess.TimeoutExpired:
        return {"error": "timeout", "verdict": "ERROR"}
    except Exception as e:
        return {"error": str(e), "verdict": "ERROR"}


def main():
    fx = json.loads(FX.read_text(encoding="utf-8"))["fixtures"]
    print(f"=== ai-skills {len(fx)} — Bandit + Semgrep 직접 측정 ===\n")

    bandit_results = []
    semgrep_results = []
    bandit_caught = bandit_clean = bandit_err = 0
    semgrep_caught = semgrep_clean = semgrep_err = 0

    is_caught = lambda v: v in ("MALICIOUS", "HIGH_RISK", "SUSPICIOUS")

    for i, item in enumerate(fx, 1):
        zip_path = ROOT / "scripts" / "eval_real_data" / item["archive_path"]
        if not zip_path.exists():
            continue

        with tempfile.TemporaryDirectory() as td:
            td_path = Path(td)
            try:
                unpack_archive(zip_path, td_path)
            except Exception as e:
                print(f"  [{i:>3}/{len(fx)}] {item['name'][:40]:40s} UNPACK ERR: {e}")
                continue

            # Bandit
            b = run_bandit(td_path)
            bandit_results.append({"name": item["name"], **b})
            v_b = b.get("verdict", "ERROR")
            if v_b == "ERROR": bandit_err += 1
            elif is_caught(v_b): bandit_caught += 1
            else: bandit_clean += 1

            # Semgrep
            s = run_semgrep(td_path)
            semgrep_results.append({"name": item["name"], **s})
            v_s = s.get("verdict", "ERROR")
            if v_s == "ERROR": semgrep_err += 1
            elif is_caught(v_s): semgrep_caught += 1
            else: semgrep_clean += 1

            print(f"  [{i:>3}/{len(fx)}] {item['name'][:40]:40s} "
                  f"Bandit={v_b:10s}(H{b.get('high',0)},M{b.get('medium',0)}) "
                  f"Semgrep={v_s:10s}({s.get('total_findings',0)})")

    # Summary
    n_b = bandit_caught + bandit_clean
    n_s = semgrep_caught + semgrep_clean
    bandit_recall = bandit_caught / max(1, n_b)
    semgrep_recall = semgrep_caught / max(1, n_s)

    print(f"\n=== Aggregate ===")
    print(f"Bandit:  TP={bandit_caught} FN={bandit_clean} ERR={bandit_err} "
          f"n={n_b}  Recall={bandit_recall:.4f}")
    print(f"Semgrep: TP={semgrep_caught} FN={semgrep_clean} ERR={semgrep_err} "
          f"n={n_s}  Recall={semgrep_recall:.4f}")

    # 저장
    out_bandit = {
        "tool": "Bandit (Python SAST)",
        "results": bandit_results,
        "tp": bandit_caught, "fn": bandit_clean, "err": bandit_err,
        "n": n_b, "recall": round(bandit_recall, 4),
    }
    out_semgrep = {
        "tool": "Semgrep (multi-lang SAST, auto config)",
        "results": semgrep_results,
        "tp": semgrep_caught, "fn": semgrep_clean, "err": semgrep_err,
        "n": n_s, "recall": round(semgrep_recall, 4),
    }
    (ROOT / "scripts" / "eval_real_data" / "results_ai_skills_bandit.json").write_text(
        json.dumps(out_bandit, ensure_ascii=False, indent=2), encoding="utf-8")
    (ROOT / "scripts" / "eval_real_data" / "results_ai_skills_semgrep.json").write_text(
        json.dumps(out_semgrep, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"\nsaved.")


if __name__ == "__main__":
    main()
