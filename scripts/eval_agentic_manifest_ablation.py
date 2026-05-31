"""Task C — Agentic 패키지 manifest ON/OFF FPR ablation.

각 정상 agentic 패키지에 대해:
  (A) manifest 없음 (current state)
  (B) manifest 있음 (generous: typical agentic capability 다 declared)

verdict 비교 → FPR 차이 = 매니페스트의 정량적 가치.

산출:
  scripts/eval_real_data/results_agentic_manifest_ablation.json
  - per-package: { name, ecosystem, verdict_off, verdict_on, matchers_off, matchers_on }
  - aggregate: FPR_off vs FPR_on
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

# eval_real.py 의 extract_archive 재사용
from eval_real import extract_archive  # type: ignore

FX_PATH = ROOT / "scripts" / "eval_real_data" / "agentic_fixtures.json"
OUT = ROOT / "scripts" / "eval_real_data" / "results_agentic_manifest_ablation.json"


# ───────────── 관대한 매니페스트 (generous) ─────────────

GENEROUS_PYPROJECT = """\
[tool.agentic]
capabilities = [
    "net.http",
    "net.socket",
    "fs.read",
    "fs.write",
    "shell.exec",
    "proc.spawn",
    "env.read",
    "secrets.read",
    "subprocess",
    "dynamic_eval",
]
network_endpoints = ["*"]
filesystem_scope = ["*"]
secrets_access = ["env"]

[tool.agentic.rule_of_two]
session_isolation = true
satisfies = "human_in_the_loop"

[tool.agentic.design_patterns]
applied = ["sandboxing", "least_privilege"]
"""

GENEROUS_PACKAGE_JSON_FIELD = {
    "agentic": {
        "capabilities": [
            "net.http", "net.socket",
            "fs.read", "fs.write",
            "shell.exec", "proc.spawn",
            "env.read", "secrets.read",
            "subprocess", "dynamic_eval",
        ],
        "network_endpoints": ["*"],
        "filesystem_scope": ["*"],
        "secrets_access": ["env"],
        "rule_of_two": {
            "session_isolation": True,
            "satisfies": "human_in_the_loop",
        },
        "design_patterns": {
            "applied": ["sandboxing", "least_privilege"],
        },
    },
}


def _inject_package_json(pkg_json_text: str | None) -> str:
    """기존 package.json 에 agentic 필드 주입."""
    try:
        d = json.loads(pkg_json_text or "{}")
    except Exception:
        d = {}
    d.update(GENEROUS_PACKAGE_JSON_FIELD)
    return json.dumps(d, ensure_ascii=False)


def _measure_one(fx: dict):
    archive_path = ROOT / "scripts" / "eval_real_data" / fx["archive_path"]
    archive_bytes = archive_path.read_bytes()
    files = extract_archive(
        archive_bytes, fx["archive_format"], fx["label"],
    )
    if not files:
        return None

    sources = files
    deps: list[str] = []
    pkg_name = fx["name"]
    eco = fx["ecosystem"]
    is_python = (eco.lower() == "pypi")
    language = "python" if is_python else "javascript"
    description = ""

    # 기존 manifest 추출 (있다면)
    pyproject_text = None
    package_json_text = None
    if is_python:
        # pyproject.toml 찾기
        for p, content in files.items():
            if p.endswith("pyproject.toml"):
                pyproject_text = content
                break
    else:
        for p, content in files.items():
            if p.endswith("package.json"):
                package_json_text = content
                # deps 추출
                try:
                    d = json.loads(content)
                    deps = list((d.get("dependencies") or {}).keys()) + \
                           list((d.get("devDependencies") or {}).keys())
                except Exception:
                    pass
                break

    # (A) manifest OFF — 기존 그대로
    off = classify(
        package_name=pkg_name,
        description=description,
        dependencies=deps,
        sources=sources,
        pyproject_text=pyproject_text,
        package_json_text=package_json_text,
        language=language,
    )

    # (B) manifest ON — generous injection
    if is_python:
        py_on = GENEROUS_PYPROJECT
        pj_on = package_json_text
    else:
        py_on = pyproject_text
        pj_on = _inject_package_json(package_json_text)

    on = classify(
        package_name=pkg_name,
        description=description,
        dependencies=deps,
        sources=sources,
        pyproject_text=py_on,
        package_json_text=pj_on,
        language=language,
    )

    return {
        "name": pkg_name,
        "ecosystem": eco,
        "version": fx.get("version"),
        "is_agentic": off.is_agentic,
        "manifest_off": {
            "verdict": off.verdict.value,
            "reason": off.reason,
            "detected": sorted(off.detected),
            "declared": sorted(off.declared),
            "undeclared": sorted(off.undeclared),
            "rule_hits": [h.rule_id for h in off.rule_report.hits]
                         if off.rule_report else [],
        },
        "manifest_on": {
            "verdict": on.verdict.value,
            "reason": on.reason,
            "detected": sorted(on.detected),
            "declared": sorted(on.declared),
            "undeclared": sorted(on.undeclared),
            "rule_hits": [h.rule_id for h in on.rule_report.hits]
                         if on.rule_report else [],
        },
    }


def main():
    if not FX_PATH.exists():
        print(f"ERROR: {FX_PATH} 없음. 먼저 fetch_agentic_archives.py 실행.")
        return
    fx_list = json.loads(FX_PATH.read_text(encoding="utf-8"))["fixtures"]
    print(f"=== Task C — Agentic manifest ablation ({len(fx_list)} 패키지) ===")

    results = []
    by_verdict_off = {}
    by_verdict_on = {}
    for i, fx in enumerate(fx_list, 1):
        t0 = time.time()
        try:
            r = _measure_one(fx)
        except Exception as e:
            print(f"  [{i:>3}/{len(fx_list)}] {fx['name']:50s} ERROR: {e}")
            results.append({"name": fx["name"], "ecosystem": fx["ecosystem"],
                            "error": str(e)})
            continue
        if r is None:
            print(f"  [{i:>3}/{len(fx_list)}] {fx['name']:50s} no source files")
            continue
        results.append(r)
        v_off = r["manifest_off"]["verdict"]
        v_on = r["manifest_on"]["verdict"]
        by_verdict_off[v_off] = by_verdict_off.get(v_off, 0) + 1
        by_verdict_on[v_on] = by_verdict_on.get(v_on, 0) + 1
        delta = " ↓" if v_off != v_on else ""
        elapsed = time.time() - t0
        print(f"  [{i:>3}/{len(fx_list)}] {fx['name'][:46]:46s} "
              f"OFF={v_off:11s} ON={v_on:11s}{delta} ({elapsed:.1f}s)")

    # aggregate
    def _fpr(by_v: dict, valid_n: int) -> tuple[int, float]:
        fp = sum(c for v, c in by_v.items()
                 if v in ("MALICIOUS", "HIGH_RISK", "SUSPICIOUS"))
        return fp, fp / max(1, valid_n)

    valid = [r for r in results if "error" not in r]
    fp_off, fpr_off = _fpr(by_verdict_off, len(valid))
    fp_on, fpr_on = _fpr(by_verdict_on, len(valid))

    print(f"\n=== Aggregate ===")
    print(f"  valid measurements: {len(valid)}/{len(fx_list)}")
    print(f"  manifest OFF: {by_verdict_off}")
    print(f"    FP = {fp_off}, FPR = {fpr_off:.4f}")
    print(f"  manifest ON:  {by_verdict_on}")
    print(f"    FP = {fp_on}, FPR = {fpr_on:.4f}")
    print(f"  ★ 매니페스트 가치 = FPR_off - FPR_on = {fpr_off - fpr_on:+.4f}")

    out = {
        "tool": "pkgsentinel (agentic ablation OFF vs ON)",
        "fixtures": results,
        "aggregate": {
            "n_valid": len(valid),
            "by_verdict_off": by_verdict_off,
            "by_verdict_on": by_verdict_on,
            "fp_off": fp_off, "fpr_off": round(fpr_off, 4),
            "fp_on": fp_on, "fpr_on": round(fpr_on, 4),
            "delta_fpr": round(fpr_off - fpr_on, 4),
        },
    }
    OUT.write_text(json.dumps(out, ensure_ascii=False, indent=2),
                   encoding="utf-8")
    print(f"\nsaved: {OUT}")


if __name__ == "__main__":
    main()
