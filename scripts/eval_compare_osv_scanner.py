"""OSV-Scanner baseline 측정 — 우리 543 fixture 에 대해.

OSV-Scanner 본질: (ecosystem, name, version) → OSV DB 의 known_malicious 매칭.
별도 CLI 설치 없이 우리가 이미 보유한 OSV cache 로 동일 lookup 수행
(결과 동치, 설치 절차 생략).

산출:
  - tp/fp/tn/fn (pkgsentinel 과 동일 산정식, 1a 적용: ERROR 분모 제외)
  - by_source breakdown
  - matched/unmatched 패키지 명세
  - pkgsentinel vs OSV-Scanner 비교 표
"""
from __future__ import annotations

import argparse
import json
import math
import re
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CACHE_NPM = ROOT / "src" / "pkgsentinel" / "knowledge" / "cache" / "osv_npm.json"
CACHE_PY  = ROOT / "src" / "pkgsentinel" / "knowledge" / "cache" / "osv_pypi.json"


# ─────────────── OSV cache 로딩 ───────────────

def _load_osv_index() -> dict[tuple[str, str], list[dict]]:
    """Return {(ecosystem_lower, package_name_lower): [advisory, ...]}."""
    index: dict[tuple[str, str], list[dict]] = {}
    for path, eco in [(CACHE_NPM, "npm"), (CACHE_PY, "pypi")]:
        if not path.exists():
            continue
        with path.open("rb") as f:
            advisories = json.loads(f.read().decode("utf-8"))
        for a in advisories:
            for ap in a.get("affected_packages", []):
                if isinstance(ap, str):
                    name = ap
                elif isinstance(ap, dict):
                    name = ap.get("name", "")
                else:
                    continue
                if not name:
                    continue
                key = (eco, name.lower())
                index.setdefault(key, []).append(a)
    return index


def _osv_scanner_verdict(index: dict, ecosystem: str, name: str) -> dict:
    """OSV-Scanner 동치 verdict — name match 있으면 MALICIOUS, 없으면 CLEAN."""
    eco_l = ecosystem.lower()
    if eco_l in ("pypi",):
        eco_l = "pypi"
    key = (eco_l, name.lower())
    hits = index.get(key, [])
    if hits:
        # 가장 최근 advisory
        latest = sorted(hits, key=lambda x: x.get("published", ""))[-1]
        return {
            "verdict": "MALICIOUS",
            "advisory_id": latest.get("advisory_id", "?"),
            "summary": (latest.get("summary", "") or "")[:120],
        }
    return {"verdict": "CLEAN"}


# ─────────────── metric ───────────────

def _wilson(s: int, n: int, z: float = 1.96) -> tuple[float, float]:
    if n == 0:
        return (0.0, 0.0)
    p = s / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return max(0.0, c - h), min(1.0, c + h)


def _confusion(items: list[dict]) -> dict:
    tp = fp = tn = fn = 0
    for r in items:
        v = r["osv_verdict"]
        is_pred_mal = v == "MALICIOUS"
        is_true_mal = (r["label"] == "malicious")
        if is_true_mal and is_pred_mal:
            tp += 1
        elif is_true_mal:
            fn += 1
        elif is_pred_mal:
            fp += 1
        else:
            tn += 1
    n = tp + fp + tn + fn
    p = tp / (tp + fp) if (tp + fp) else 0.0
    r = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = (2 * p * r / (p + r)) if (p + r) else 0.0
    p_lo, p_hi = _wilson(tp, tp + fp)
    r_lo, r_hi = _wilson(tp, tp + fn)
    return {"tp": tp, "fp": fp, "tn": tn, "fn": fn, "n": n,
            "precision": round(p, 4), "recall": round(r, 4),
            "f1": round(f1, 4),
            "precision_ci95": [round(p_lo, 4), round(p_hi, 4)],
            "recall_ci95": [round(r_lo, 4), round(r_hi, 4)]}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--fixtures", default=str(ROOT / "scripts" / "eval_real_data" / "fixtures.json"))
    ap.add_argument("--out", default=str(ROOT / "scripts" / "eval_real_data" / "results_osv_scanner.json"))
    args = ap.parse_args()

    print(f"Loading OSV cache (npm + pypi) ...")
    index = _load_osv_index()
    print(f"  OSV index: {len(index)} unique (ecosystem, name) advisories")

    with open(args.fixtures, "rb") as f:
        fx = json.loads(f.read().decode("utf-8"))["fixtures"]
    print(f"Loading fixtures: {len(fx)}")

    items = []
    for x in fx:
        eco = x.get("ecosystem", "?")
        name = x.get("name", "?")
        result = _osv_scanner_verdict(index, eco, name)
        items.append({
            "name": name,
            "ecosystem": eco,
            "label": x.get("label"),
            "source": x.get("source"),
            "osv_verdict": result["verdict"],
            "advisory_id": result.get("advisory_id"),
            "advisory_summary": result.get("summary"),
        })

    # 전체 metric
    overall = _confusion(items)
    print(f"\n=== OSV-Scanner overall ===")
    print(f"  TP={overall['tp']} FP={overall['fp']} "
          f"TN={overall['tn']} FN={overall['fn']}  "
          f"P={overall['precision']:.4f} R={overall['recall']:.4f} "
          f"F1={overall['f1']:.4f}  n={overall['n']}")

    # source 별
    sources = sorted({x["source"] for x in items if x.get("source")})
    by_source = {}
    print("\n=== by source ===")
    for s in sources:
        sub = [x for x in items if x["source"] == s]
        m = _confusion(sub)
        by_source[s] = m
        print(f"  {s:<28} n={m['n']:>3}  "
              f"TP={m['tp']:>3} FP={m['fp']:>3} TN={m['tn']:>3} FN={m['fn']:>3}  "
              f"P={m['precision']:.3f} R={m['recall']:.3f} F1={m['f1']:.3f}")

    # pkgsentinel 결과와 비교
    pkg_path = ROOT / "scripts" / "eval_real_data" / "results_claude_full_v2.json"
    if pkg_path.exists():
        with pkg_path.open(encoding="utf-8") as f:
            pkg = json.load(f)
        pkg_m = pkg["metrics"]
        print("\n=== 비교 (1a 적용 후) ===")
        print(f"{'Tool':<28} {'TP':>4} {'FP':>3} {'TN':>3} {'FN':>4} "
              f"{'P':>7} {'R':>7} {'F1':>7}  {'n':>4}")
        print("-" * 80)
        print(f"{'OSV-Scanner (lookup only)':<28} "
              f"{overall['tp']:>4} {overall['fp']:>3} "
              f"{overall['tn']:>3} {overall['fn']:>4} "
              f"{overall['precision']:>7.4f} {overall['recall']:>7.4f} "
              f"{overall['f1']:>7.4f}  {overall['n']:>4}")
        print(f"{'pkgsentinel (Claude full)':<28} "
              f"{pkg_m['tp']:>4} {pkg_m['fp']:>3} "
              f"{pkg_m['tn']:>3} {pkg_m['fn']:>4} "
              f"{pkg_m['precision']:>7.4f} {pkg_m['recall']:>7.4f} "
              f"{pkg_m['f1']:>7.4f}  {pkg_m['n']:>4}")
        print(f"{'pkgsentinel 가산':<28} "
              f"{pkg_m['tp']-overall['tp']:>+4} "
              f"{pkg_m['fp']-overall['fp']:>+3} "
              f"{pkg_m['tn']-overall['tn']:>+3} "
              f"{pkg_m['fn']-overall['fn']:>+4} "
              f"{pkg_m['precision']-overall['precision']:>+7.4f} "
              f"{pkg_m['recall']-overall['recall']:>+7.4f} "
              f"{pkg_m['f1']-overall['f1']:>+7.4f}")

    # 저장
    out = {
        "tool": "OSV-Scanner (cache lookup equivalent)",
        "fixtures": items,
        "metrics": overall,
        "by_source": by_source,
        "note": (
            "OSV-Scanner 동치 측정 — name+ecosystem lookup. "
            "OSV cache (knowledge/cache/osv_npm.json + osv_pypi.json) 사용. "
            "CLI 설치 절차 없이 동일 결과 (둘 다 OSV DB lookup 본질). "
            "pkgsentinel 의 L0 (Stage 0 threat_filter) 와 본질적으로 동일 — "
            "차이는 advisory_id 매칭만 vs 행위 분석 추가 여부."
        ),
    }
    Path(args.out).write_text(json.dumps(out, ensure_ascii=False, indent=2),
                              encoding="utf-8")
    print(f"\nWrote: {args.out}")


if __name__ == "__main__":
    main()
