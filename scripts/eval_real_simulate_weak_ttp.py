"""1c 정책 (weak TTP 누적 + n_files 정규화) 시뮬레이션.

실제 verdict_rules 수정 전에 results JSON 만으로 가상 효과 측정.

규칙 (조심스러운 버전):
  current verdict 가 CLEAN 인데
    (a) ttp_match >= TTP_MIN  AND
    (b) ttp_match / max(n_files, 1) >= TTP_DENSITY_MIN
  → SUSPICIOUS 로 격상 (LLM BENIGN 덮어쓰기 우회)

여러 (TTP_MIN, TTP_DENSITY_MIN) 조합 sweep 해서 recall/precision 변화 측정.
overfit 위험 평가용.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path


def _confusion(items: list[dict]) -> dict:
    tp = fp = tn = fn = 0
    errored = 0
    for r in items:
        v = r.get("verdict") or ""
        if v == "ERROR":
            errored += 1
            continue
        if v == "CANNOT_ANALYZE":
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
    n = tp + fp + tn + fn
    p = tp / (tp + fp) if (tp + fp) else 0.0
    r = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = (2 * p * r / (p + r)) if (p + r) else 0.0
    return {"tp": tp, "fp": fp, "tn": tn, "fn": fn, "n": n,
            "precision": p, "recall": r, "f1": f1}


def _apply_weak_ttp(items: list[dict],
                    ttp_min: int,
                    density_min: float) -> tuple[list[dict], list[dict], list[dict]]:
    """현 CLEAN 중 조건 만족하는 케이스를 SUSPICIOUS 로 격상한 변형 반환.

    Returns (modified items, list of promoted, list of new_fp).
    """
    promoted: list[dict] = []
    new_fp: list[dict] = []
    out = []
    for r in items:
        r2 = dict(r)
        if r.get("verdict") != "CLEAN":
            out.append(r2)
            continue
        m = r.get("matchers") or {}
        ttp = m.get("ttp_match", 0) or 0
        n_files = r.get("n_files", 0) or 0
        density = (ttp / max(1, n_files))
        if ttp >= ttp_min and density >= density_min:
            r2["verdict"] = "SUSPICIOUS"
            r2["_promoted_by_1c"] = True
            promoted.append(r2)
            if r.get("label") == "benign":
                new_fp.append(r2)
        out.append(r2)
    return out, promoted, new_fp


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--in", dest="inp", required=True)
    args = ap.parse_args()

    src = Path(args.inp)
    with src.open(encoding="utf-8") as f:
        data = json.load(f)
    items = data["fixtures"]

    baseline = _confusion(items)
    print(f"=== Baseline (현 상태, 1a 적용 후) ===")
    print(f"  TP={baseline['tp']} FP={baseline['fp']} "
          f"TN={baseline['tn']} FN={baseline['fn']}  "
          f"P={baseline['precision']:.4f} R={baseline['recall']:.4f} "
          f"F1={baseline['f1']:.4f}  n={baseline['n']}")
    print()

    print("=== 1c sweep — (ttp_min, density_min) → effect ===")
    print(f"{'TTP>=':>5} {'dens>=':>6} | "
          f"{'promoted':>8} {'truePos':>7} {'new_fp':>6} | "
          f"{'TP':>4} {'FP':>3} {'FN':>4} | "
          f"{'P':>6} {'R':>6} {'F1':>6} | {'dR':>7} {'dP':>7}")
    print("-" * 110)

    for ttp_min in [3, 5, 8, 10]:
        for density_min in [0.1, 0.2, 0.3, 0.5, 0.8, 1.0]:
            modified, promoted, new_fp = _apply_weak_ttp(items, ttp_min, density_min)
            metrics = _confusion(modified)
            n_true_pos = sum(1 for p in promoted if p.get("label")=="malicious")
            dr = metrics["recall"] - baseline["recall"]
            dp = metrics["precision"] - baseline["precision"]
            mark = ""
            if dr > 0 and dp >= -0.005:
                mark = "  ★"
            elif dp < -0.01:
                mark = "  ⚠"
            print(f"{ttp_min:>5} {density_min:>6.2f} | "
                  f"{len(promoted):>8} {n_true_pos:>5} {len(new_fp):>6} | "
                  f"{metrics['tp']:>4} {metrics['fp']:>3} {metrics['fn']:>4} | "
                  f"{metrics['precision']:>6.4f} {metrics['recall']:>6.4f} "
                  f"{metrics['f1']:>6.4f} | {dr:+7.4f} {dp:+7.4f}{mark}")

    print()
    print("★ = recall ↑ + precision 거의 유지   ⚠ = precision 크게 하락")

    # 가장 좋은 setting 의 promoted/new_fp 자세히
    print()
    print("=== 추천 setting (ttp>=5, density>=0.5) 상세 ===")
    modified, promoted, new_fp = _apply_weak_ttp(items, 5, 0.5)
    n_true_pos = sum(1 for p in promoted if p.get("label")=="malicious")
    print(f"격상된 패키지: {len(promoted)}건  (true positive {n_true_pos}, new FP {len(new_fp)})")
    print()
    print(f"--- new TP ({n_true_pos}건) — 회복된 FN ---")
    for p in [x for x in promoted if x.get("label")=="malicious"][:15]:
        m = p.get("matchers") or {}
        print(f"  {p['ecosystem']:4s} {p['name']:35s} "
              f"ttp={m.get('ttp_match',0)} n_files={p.get('n_files',0)} "
              f"density={(m.get('ttp_match',0)/max(1,p.get('n_files',0))):.2f} "
              f"llm={m.get('llm_stub','?')}")
    if new_fp:
        print()
        print(f"--- new FP ({len(new_fp)}건) — 새로 잘못 잡은 정상 ---")
        for p in new_fp:
            m = p.get("matchers") or {}
            print(f"  {p['ecosystem']:4s} {p['name']:35s} "
                  f"ttp={m.get('ttp_match',0)} n_files={p.get('n_files',0)} "
                  f"density={(m.get('ttp_match',0)/max(1,p.get('n_files',0))):.2f} "
                  f"llm={m.get('llm_stub','?')}")


if __name__ == "__main__":
    main()
