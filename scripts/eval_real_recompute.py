"""기존 results JSON 의 fixture 결과를 들고 metric 만 재계산.

전체 재측정은 LLM 호출 비용/시간이 큼 (claude full 54분).
verdict 자체는 변경 없이 metric 산식만 정정할 때 사용.

1a 정정 — ERROR / CANNOT_ANALYZE 를 confusion 분모에서 제외.

사용:
    python scripts/eval_real_recompute.py \
        --in scripts/eval_real_data/results_claude_full.json \
        --out scripts/eval_real_data/results_claude_full_v2.json
"""
from __future__ import annotations

import argparse
import json
import math
from collections import Counter
from pathlib import Path


def _wilson_interval(successes: int, total: int,
                     z: float = 1.96) -> tuple[float, float]:
    if total == 0:
        return (0.0, 0.0)
    p = successes / total
    denom = 1 + z * z / total
    centre = (p + z * z / (2 * total)) / denom
    half = (z * math.sqrt(p * (1 - p) / total + z * z / (4 * total * total))
            / denom)
    return max(0.0, centre - half), min(1.0, centre + half)


def _confusion(items: list[dict]) -> dict:
    """1a 정정 — ERROR/CANNOT_ANALYZE 분리."""
    tp = fp = tn = fn = 0
    errored = 0
    cannot_analyzed = 0
    for r in items:
        v = r.get("verdict") or ""
        if v == "ERROR":
            errored += 1
            continue
        if v == "CANNOT_ANALYZE":
            cannot_analyzed += 1
            continue
        is_mal_pred = v in ("MALICIOUS", "HIGH_RISK", "SUSPICIOUS")
        is_mal_true = (r.get("label") == "malicious")
        if is_mal_true and is_mal_pred:
            tp += 1
        elif is_mal_true and not is_mal_pred:
            fn += 1
        elif (not is_mal_true) and is_mal_pred:
            fp += 1
        else:
            tn += 1
    p = tp / (tp + fp) if (tp + fp) else 0.0
    r = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = (2 * p * r / (p + r)) if (p + r) else 0.0
    n_analyzed = tp + fp + tn + fn
    acc = (tp + tn) / max(1, n_analyzed)
    p_lo, p_hi = _wilson_interval(tp, tp + fp)
    r_lo, r_hi = _wilson_interval(tp, tp + fn)
    return {
        "tp": tp, "tn": tn, "fp": fp, "fn": fn,
        "precision": round(p, 4),
        "recall": round(r, 4),
        "f1": round(f1, 4),
        "accuracy": round(acc, 4),
        "n": n_analyzed,
        "n_total": len(items),
        "errored": errored,
        "cannot_analyzed": cannot_analyzed,
        "excluded": errored + cannot_analyzed,
        "precision_ci95": [round(p_lo, 4), round(p_hi, 4)],
        "recall_ci95": [round(r_lo, 4), round(r_hi, 4)],
    }


def _by_source(items: list[dict]) -> dict:
    out = {}
    sources = sorted({(x.get("source") or "?") for x in items})
    for s in sources:
        sub = [x for x in items if (x.get("source") or "?") == s]
        out[s] = _confusion(sub)
    return out


def _print_summary(old: dict, new: dict, label: str = "") -> None:
    print(f"\n=== {label} ===")
    print(f"  before: tp={old['tp']:>4} fp={old['fp']:>3} "
          f"tn={old['tn']:>3} fn={old['fn']:>4}   "
          f"P={old['precision']:.4f}  R={old['recall']:.4f}  "
          f"F1={old['f1']:.4f}  n={old['n']}")
    excluded = new.get("excluded", 0)
    print(f"  after : tp={new['tp']:>4} fp={new['fp']:>3} "
          f"tn={new['tn']:>3} fn={new['fn']:>4}   "
          f"P={new['precision']:.4f}  R={new['recall']:.4f}  "
          f"F1={new['f1']:.4f}  n={new['n']}  "
          f"(분모 제외: {excluded} = ERROR {new.get('errored',0)} "
          f"+ CANNOT_ANALYZE {new.get('cannot_analyzed',0)})")
    dr = new['recall'] - old['recall']
    dp = new['precision'] - old['precision']
    print(f"  delta : recall {dr:+.4f}   precision {dp:+.4f}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--in", dest="inp", required=True)
    ap.add_argument("--out", dest="out", required=True)
    args = ap.parse_args()

    src = Path(args.inp)
    dst = Path(args.out)

    with src.open(encoding="utf-8") as f:
        data = json.load(f)

    items = data["fixtures"]
    old_metrics = data.get("metrics", {})
    old_by_src = data.get("by_source", {})

    new_metrics = _confusion(items)
    new_by_src = _by_source(items)

    print(f"Input : {src}")
    print(f"Output: {dst}")
    print(f"Total fixtures: {len(items)}")
    print(f"verdict 분포: {Counter(x.get('verdict','?') for x in items)}")

    _print_summary(old_metrics, new_metrics, "Overall")
    print("\n=== Per-source ===")
    for s in sorted(new_by_src):
        old_s = old_by_src.get(s, {})
        new_s = new_by_src[s]
        if not old_s:
            old_s = {"tp": "?", "fp": "?", "tn": "?", "fn": "?",
                     "precision": 0.0, "recall": 0.0, "f1": 0.0, "n": "?"}
        _print_summary(old_s, new_s, s)

    out_data = {
        **data,
        "metrics": new_metrics,
        "by_source": new_by_src,
        "recompute_note": (
            "1a 정정: ERROR / CANNOT_ANALYZE 를 confusion 분모에서 제외. "
            "도구 detection 능력 측정과 무관 (분석할 코드 없음 / 분석 실패)."
        ),
    }
    dst.write_text(json.dumps(out_data, ensure_ascii=False, indent=2),
                   encoding="utf-8")
    print(f"\nWrote: {dst}")


if __name__ == "__main__":
    main()
