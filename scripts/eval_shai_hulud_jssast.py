"""Shai-Hulud 162 (npm, OSV-disjoint) — njsscan + Semgrep(JS) 행위 기반 측정.

DB 기반 도구(npm audit/OSV)는 이미 등재되어 trivial → 행위/정적 기반 JS 도구로
공정한 retrospective zero-day 비교.

verdict 정책 (ai-skills 측정과 동일):
  finding(severity ERROR) >= 1 → MALICIOUS
  finding(WARNING/INFO)   >= 1 → SUSPICIOUS
  else                          → CLEAN
  추출 가능 소스 없음 / 도구 오류 → ERROR (분모 제외)

ground truth: 전부 malicious → catch(MAL/SUS)=TP, miss(CLEAN)=FN

산출:
  results_shai_hulud_njsscan.json
  results_shai_hulud_semgrep.json
"""
from __future__ import annotations

import json
import subprocess
import tempfile
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
FX = ROOT / "scripts" / "eval_real_data" / "shai_hulud_dd_fixtures.json"
OUT_DIR = ROOT / "scripts" / "eval_real_data"


def unpack(zip_path: Path, dest: Path):
    with zipfile.ZipFile(zip_path, "r") as z:
        z.setpassword(b"infected")
        z.extractall(dest)


def run_njsscan(target: Path) -> dict:
    try:
        r = subprocess.run(
            ["njsscan", "--json", str(target)],
            capture_output=True, text=True, timeout=120,
        )
        out = json.loads(r.stdout) if r.stdout else {}
        sev = {"ERROR": 0, "WARNING": 0, "INFO": 0}
        total = 0
        for section in ("nodejs", "templates"):
            for rule, info in (out.get(section) or {}).items():
                files = info.get("files", []) if isinstance(info, dict) else []
                hits = max(1, len(files))
                total += hits
                s = ((info.get("metadata", {}) or {}).get("severity") or "").upper()
                if s in sev:
                    sev[s] += hits
        if sev["ERROR"] >= 1:
            verdict = "MALICIOUS"
        elif sev["WARNING"] >= 1 or sev["INFO"] >= 1 or total >= 1:
            verdict = "SUSPICIOUS"
        else:
            verdict = "CLEAN"
        return {"verdict": verdict, "error_sev": sev["ERROR"],
                "warning": sev["WARNING"], "info": sev["INFO"],
                "total_findings": total}
    except subprocess.TimeoutExpired:
        return {"verdict": "ERROR", "error": "timeout"}
    except Exception as e:
        return {"verdict": "ERROR", "error": str(e)[:200]}


def run_semgrep(target: Path) -> dict:
    try:
        r = subprocess.run(
            ["semgrep", "scan",
             "--config", "p/javascript",
             "--config", "p/security-audit",
             "--json", "--quiet", "--disable-version-check",
             "--metrics", "off", str(target)],
            capture_output=True, text=True, timeout=180,
        )
        if r.returncode > 1 and not r.stdout:
            return {"verdict": "ERROR", "error": r.stderr[:200]}
        out = json.loads(r.stdout) if r.stdout else {}
        findings = out.get("results", [])
        sev = {"ERROR": 0, "WARNING": 0, "INFO": 0}
        for f in findings:
            s = (f.get("extra", {}).get("severity") or "").upper()
            if s in sev:
                sev[s] += 1
        if sev["ERROR"] >= 1:
            verdict = "MALICIOUS"
        elif sev["WARNING"] >= 1 or sev["INFO"] >= 1 or len(findings) >= 1:
            verdict = "SUSPICIOUS"
        else:
            verdict = "CLEAN"
        return {"verdict": verdict, "error_sev": sev["ERROR"],
                "warning": sev["WARNING"], "info": sev["INFO"],
                "total_findings": len(findings)}
    except subprocess.TimeoutExpired:
        return {"verdict": "ERROR", "error": "timeout"}
    except Exception as e:
        return {"verdict": "ERROR", "error": str(e)[:200]}


def main():
    fx = json.loads(FX.read_text(encoding="utf-8"))["fixtures"]
    print(f"=== Shai-Hulud {len(fx)} — njsscan + Semgrep(JS) ===", flush=True)

    nj_results, sg_results = [], []
    nj = [0, 0, 0]  # tp, fn, err
    sg = [0, 0, 0]
    is_tp = lambda v: v in ("MALICIOUS", "HIGH_RISK", "SUSPICIOUS")

    for i, item in enumerate(fx, 1):
        zp = ROOT / "scripts" / "eval_real_data" / item["archive_path"]
        if not zp.exists():
            continue
        with tempfile.TemporaryDirectory() as td:
            tdp = Path(td)
            try:
                unpack(zp, tdp)
            except Exception as e:
                print(f"  [{i:>3}] {item['name'][:35]:35s} UNPACK ERR {e}", flush=True)
                nj[2] += 1; sg[2] += 1
                continue
            n = run_njsscan(tdp)
            s = run_semgrep(tdp)
        nj_results.append({"name": item["name"], **n})
        sg_results.append({"name": item["name"], **s})
        for res, acc in ((n, nj), (s, sg)):
            v = res.get("verdict", "ERROR")
            if v == "ERROR": acc[2] += 1
            elif is_tp(v): acc[0] += 1
            else: acc[1] += 1
        print(f"  [{i:>3}/{len(fx)}] {item['name'][:35]:35s} "
              f"njsscan={n.get('verdict'):10s}({n.get('total_findings',0)}) "
              f"semgrep={s.get('verdict'):10s}({s.get('total_findings',0)})", flush=True)

    for name, acc, results, fname in (
        ("njsscan (Node.js SAST)", nj, nj_results, "results_shai_hulud_njsscan.json"),
        ("Semgrep JS (p/javascript)", sg, sg_results, "results_shai_hulud_semgrep.json"),
    ):
        tp, fn, err = acc
        n = tp + fn
        recall = tp / max(1, n)
        print(f"\n{name}: TP={tp} FN={fn} ERR={err} n={n} Recall={recall:.4f}", flush=True)
        (OUT_DIR / fname).write_text(json.dumps({
            "tool": name, "results": results,
            "tp": tp, "fn": fn, "err": err, "n": n, "recall": round(recall, 4),
        }, ensure_ascii=False, indent=2), encoding="utf-8")
    print("\nsaved.", flush=True)


if __name__ == "__main__":
    main()
