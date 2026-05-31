"""Socket 측정 — npm 만 (PyPI /purl 비싸서 제외).

Task A: 543 fixture 의 npm 280개 전체 (compromised 50 + intent 200 + benign 30)
Task C: agentic npm 패키지 (별도 list)

quota 회복 고려한 rate limit 자동 처리.
"""
from __future__ import annotations

import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from eval_compare_socket import get_npm_score, get_quota, score_to_verdict

ROOT = Path(__file__).resolve().parent.parent


def measure_npm(items: list[dict], out_path: Path, label: str,
                sleep_s: float = 1.0, quota_floor: int = 30) -> None:
    """npm 패키지 list 측정. quota 잔량 < floor 면 30초 sleep."""
    print(f"\n=== {label} ({len(items)} npm 패키지) ===")
    q0 = get_quota()
    print(f"  starting quota: {q0.get('quota')}/{q0.get('maxQuota')}")

    results = []
    ok = 0; fail = 0
    for i, fx in enumerate(items, 1):
        # quota safety
        if i % 20 == 0:
            q = get_quota()
            rem = q.get("quota", 0)
            if rem < quota_floor:
                print(f"  ⏸ quota 잔량 {rem} < {quota_floor}, 30초 대기")
                time.sleep(30)
                q = get_quota()
                print(f"  ▶ 재개. quota: {q.get('quota')}")

        name = fx["name"]; version = fx.get("version", "latest")
        r = get_npm_score(name, version)
        item = {
            "name": name, "ecosystem": "npm", "version": version,
            "label": fx.get("label"),
            "source": fx.get("source"),
            "verdict": r.get("verdict"),
            "score": r.get("score"),
            "critical": r.get("critical_issues"),
            "high": r.get("high_issues"),
        }
        results.append(item)
        if r.get("verdict") not in ("ERROR", "PARSE_ERROR", "UNKNOWN"):
            ok += 1
        else:
            fail += 1
        if i % 25 == 0:
            q = get_quota()
            print(f"  [{i:>3}/{len(items)}] ok={ok} fail={fail} "
                  f"quota={q.get('quota')}")
        time.sleep(sleep_s)

    q1 = get_quota()
    print(f"\n  done. ok={ok} fail={fail}. "
          f"quota: {q0.get('quota')} → {q1.get('quota')}")

    # confusion
    tp = fp = tn = fn = 0
    for r in results:
        v = r.get("verdict", "")
        if v in ("ERROR", "PARSE_ERROR", "UNKNOWN"):
            continue
        is_pred = v in ("MALICIOUS", "HIGH_RISK", "SUSPICIOUS")
        is_true = (r.get("label") == "malicious")
        if is_true and is_pred: tp += 1
        elif is_true: fn += 1
        elif is_pred: fp += 1
        else: tn += 1
    n = tp + fp + tn + fn
    p = tp / (tp + fp) if (tp + fp) else 0.0
    rcl = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = (2 * p * rcl / (p + rcl)) if (p + rcl) else 0.0
    print(f"  Confusion: TP={tp} FP={fp} TN={tn} FN={fn}")
    print(f"  P={p:.4f} R={rcl:.4f} F1={f1:.4f}  n={n}")

    # source breakdown
    print("\n  Per-source:")
    sources = sorted({(r.get("source") or "?") for r in results})
    by_src = {}
    for s in sources:
        sub = [r for r in results if (r.get("source") or "?") == s]
        s_tp = sum(1 for r in sub if r.get("label")=="malicious"
                   and r.get("verdict") in ("MALICIOUS","HIGH_RISK","SUSPICIOUS"))
        s_fn = sum(1 for r in sub if r.get("label")=="malicious"
                   and r.get("verdict") not in ("MALICIOUS","HIGH_RISK","SUSPICIOUS","ERROR","PARSE_ERROR","UNKNOWN"))
        s_fp = sum(1 for r in sub if r.get("label")=="benign"
                   and r.get("verdict") in ("MALICIOUS","HIGH_RISK","SUSPICIOUS"))
        s_tn = sum(1 for r in sub if r.get("label")=="benign"
                   and r.get("verdict") == "CLEAN")
        s_n = s_tp + s_fp + s_tn + s_fn
        s_rcl = s_tp/(s_tp+s_fn) if (s_tp+s_fn) else 0.0
        s_p = s_tp/(s_tp+s_fp) if (s_tp+s_fp) else 0.0
        print(f"    {s:<28} n={s_n:>3} TP={s_tp} FN={s_fn} FP={s_fp} TN={s_tn} "
              f"R={s_rcl:.3f} P={s_p:.3f}")
        by_src[s] = {"tp": s_tp, "fp": s_fp, "tn": s_tn, "fn": s_fn,
                     "recall": round(s_rcl,4), "precision": round(s_p,4)}

    out = {
        "tool": "Socket.dev API (npm only)",
        "label": label,
        "fixtures": results,
        "metrics": {"tp": tp, "fp": fp, "tn": tn, "fn": fn,
                    "precision": round(p, 4), "recall": round(rcl, 4),
                    "f1": round(f1, 4), "n": n},
        "by_source": by_src,
        "quota_start": q0, "quota_end": q1,
    }
    out_path.write_text(json.dumps(out, ensure_ascii=False, indent=2),
                        encoding="utf-8")
    print(f"\n  saved: {out_path}")


def main():
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--mode", choices=["taskA"], default="taskA")
    args = ap.parse_args()

    if args.mode == "taskA":
        # 543 fixture 의 npm 280개 전체
        fx = json.loads((ROOT / "scripts" / "eval_real_data" / "fixtures.json")
                        .read_text(encoding="utf-8"))["fixtures"]
        npm_fx = [x for x in fx if x.get("ecosystem") == "npm"]
        out = ROOT / "scripts" / "eval_real_data" / "results_socket_npm.json"
        measure_npm(npm_fx, out, label="Task A — npm 280", sleep_s=1.0)


if __name__ == "__main__":
    main()
