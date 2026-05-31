"""Perfectly honest author simulation — 각 패키지의 detected (canonical) 와
정확히 일치하는 declared 로 manifest 작성 → 매니페스트 효과의 upper bound 측정.

기존 ablation:
  generous manifest (10개 capability 일률) — 일부 detected 가 빠짐 → R2-1 발화
이번:
  per-package manifest (detected 그대로 declared) — undeclared = ∅ → R2-1 차단

비교:
  - OFF (매니페스트 없음)
  - generous (10개 capability — 기존)
  - PERFECT (per-package detected)
"""
from __future__ import annotations

import json
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "scripts"))

from pkgsentinel.agentic.classifier import classify
from eval_real import extract_archive  # type: ignore


def _pyproject_from_caps(canonical_caps: list[str]) -> str:
    """canonical capability 들로 [tool.agentic] pyproject 텍스트 생성.

    rule_of_two 와 design_patterns 도 정직히 채워서 R3-rot-mismatch 회피.
    """
    caps_str = ",\n    ".join(f'"{c}"' for c in sorted(canonical_caps))
    return f"""[tool.agentic]
agentic = true
spec_version = "0.2"
capabilities = [
    {caps_str}
]

[tool.agentic.rule_of_two]
session_isolation = true
satisfies = ["A", "B"]

[tool.agentic.design_patterns]
applied = ["sandboxing", "least_privilege", "human_in_the_loop"]

[tool.agentic.tool_registry]
dynamic_tools = false
tool_signature_verification = true
trusted_tool_sources = ["registry"]
"""


def _package_json_from_caps(canonical_caps: list[str]) -> str:
    """package.json + agentic 필드."""
    return json.dumps({
        "name": "perfectly-honest-pkg",
        "agentic": {
            "agentic": True,
            "specVersion": "0.2",
            "capabilities": sorted(canonical_caps),
            "ruleOfTwo": {
                "sessionIsolation": True,
                "satisfies": ["A", "B"],
            },
            "designPatterns": {
                "applied": ["sandboxing", "least_privilege", "human_in_the_loop"],
            },
            "toolRegistry": {
                "dynamicTools": False,
                "toolSignatureVerification": True,
                "trustedToolSources": ["registry"],
            },
        },
    }, ensure_ascii=False, indent=2)


def measure(fx_path: Path, out_path: Path):
    fx = json.loads(fx_path.read_text(encoding="utf-8"))["fixtures"]
    print(f"=== Perfectly honest manifest simulation ({len(fx)} 패키지) ===")

    results = []
    by_verdict_off = {}
    by_verdict_perfect = {}

    for i, item in enumerate(fx, 1):
        archive_path = ROOT / "scripts" / "eval_real_data" / item["archive_path"]
        try:
            files = extract_archive(
                archive_path.read_bytes(), item["archive_format"], item["label"],
            )
        except Exception as e:
            print(f"  [{i:>3}/{len(fx)}] {item['name']:42s} EXTRACT ERR: {e}")
            continue
        if not files:
            continue

        # 기존 manifest 추출
        pyproject_text = None
        package_json_text = None
        deps = []
        is_python = (item["ecosystem"].lower() == "pypi")
        language = "python" if is_python else "javascript"
        for p, content in files.items():
            if p.endswith("pyproject.toml"):
                pyproject_text = content
            elif p.endswith("package.json"):
                package_json_text = content
                try:
                    d = json.loads(content)
                    deps = list((d.get("dependencies") or {}).keys()) + \
                           list((d.get("devDependencies") or {}).keys())
                except Exception:
                    pass

        # (A) manifest OFF
        off = classify(
            package_name=item["name"], description="", dependencies=deps,
            sources=files, pyproject_text=pyproject_text,
            package_json_text=package_json_text, language=language,
        )

        # (B) Perfectly honest manifest — detected (canonical) 정확 일치
        detected = sorted(off.detected)
        if not detected:
            # detected 없으면 perfect manifest 도 빈 declared
            detected = []

        if is_python:
            perfect_pp = _pyproject_from_caps(detected)
            perfect_pj = package_json_text
        else:
            perfect_pp = pyproject_text
            perfect_pj = _package_json_from_caps(detected)

        perfect = classify(
            package_name=item["name"], description="", dependencies=deps,
            sources=files, pyproject_text=perfect_pp,
            package_json_text=perfect_pj, language=language,
        )

        v_off = off.verdict.value
        v_perf = perfect.verdict.value
        by_verdict_off[v_off] = by_verdict_off.get(v_off, 0) + 1
        by_verdict_perfect[v_perf] = by_verdict_perfect.get(v_perf, 0) + 1

        delta = " ↓" if v_off != v_perf and v_perf in ("CLEAN", "AGENTIC") else \
                (" ↑" if v_off != v_perf else "")
        print(f"  [{i:>3}/{len(fx)}] {item['name'][:40]:40s} "
              f"OFF={v_off:11s} PERFECT={v_perf:11s}{delta}  "
              f"detected={len(detected)}")

        results.append({
            "name": item["name"], "ecosystem": item["ecosystem"],
            "label": item["label"],
            "detected": detected,
            "off": {"verdict": v_off, "reason": off.reason},
            "perfect": {"verdict": v_perf, "reason": perfect.reason},
        })

    # Aggregate
    is_caught = lambda v: v in ("MALICIOUS","HIGH_RISK","SUSPICIOUS")
    n = len(results)
    off_fp = sum(1 for r in results
                 if r["label"]=="benign" and is_caught(r["off"]["verdict"]))
    perf_fp = sum(1 for r in results
                  if r["label"]=="benign" and is_caught(r["perfect"]["verdict"]))
    off_tp = sum(1 for r in results
                 if r["label"]=="malicious" and is_caught(r["off"]["verdict"]))
    perf_tp = sum(1 for r in results
                  if r["label"]=="malicious" and is_caught(r["perfect"]["verdict"]))
    benign_n = sum(1 for r in results if r["label"]=="benign")
    mal_n    = sum(1 for r in results if r["label"]=="malicious")

    print(f"\n=== Aggregate ===")
    print(f"  by_verdict OFF:     {by_verdict_off}")
    print(f"  by_verdict PERFECT: {by_verdict_perfect}")
    print()
    if benign_n:
        print(f"  FPR OFF:     {off_fp}/{benign_n} = {off_fp/benign_n:.4f}")
        print(f"  FPR PERFECT: {perf_fp}/{benign_n} = {perf_fp/benign_n:.4f}  "
              f"(Δ {(perf_fp-off_fp)/benign_n:+.4f}) ★")
    if mal_n:
        print(f"  Recall OFF:     {off_tp}/{mal_n} = {off_tp/mal_n:.4f}")
        print(f"  Recall PERFECT: {perf_tp}/{mal_n} = {perf_tp/mal_n:.4f}  "
              f"(Δ {(perf_tp-off_tp)/mal_n:+.4f})")

    out_data = {
        "policy": "Perfectly honest author manifest (detected = declared exact)",
        "fixtures": results,
        "by_verdict_off": by_verdict_off,
        "by_verdict_perfect": by_verdict_perfect,
        "benign_n": benign_n,
        "malicious_n": mal_n,
        "off_fp": off_fp, "perfect_fp": perf_fp,
        "off_tp": off_tp, "perfect_tp": perf_tp,
    }
    out_path.write_text(json.dumps(out_data, ensure_ascii=False, indent=2),
                        encoding="utf-8")
    print(f"\nsaved: {out_path}")


def main():
    benign_fx = ROOT / "scripts" / "eval_real_data" / "agentic_fixtures.json"
    benign_out = ROOT / "scripts" / "eval_real_data" / "results_perfect_honest_benign.json"
    measure(benign_fx, benign_out)

    print()
    mal_fx = ROOT / "scripts" / "eval_real_data" / "agentic_malicious_fixtures.json"
    mal_out = ROOT / "scripts" / "eval_real_data" / "results_perfect_honest_malicious.json"
    measure(mal_fx, mal_out)


if __name__ == "__main__":
    main()
