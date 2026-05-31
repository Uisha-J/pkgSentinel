"""Socket 측정 — multievent 150 npm 패키지. cluster 별 recall."""
from __future__ import annotations

import json
import sys
import time
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from eval_compare_socket import get_npm_score, get_quota

ROOT = Path(__file__).resolve().parent.parent
FX = ROOT / "scripts" / "eval_real_data" / "multievent_fixtures.json"
OUT = ROOT / "scripts" / "eval_real_data" / "results_socket_multievent.json"


def main():
    fx = json.loads(FX.read_text(encoding="utf-8"))["fixtures"]
    print(f"Socket on multievent {len(fx)}", flush=True)
    q0 = get_quota()
    print(f"quota: {q0.get('quota')}", flush=True)

    results = []
    tp = fn = err = 0
    by_cluster = defaultdict(lambda: [0, 0, 0])  # [tp, fn, err]
    for i, x in enumerate(fx, 1):
        if i % 30 == 0:
            q = get_quota()
            print(f"  [{i}/{len(fx)}] quota={q.get('quota')} tp={tp} fn={fn} err={err}",
                  flush=True)
            if q.get("quota", 0) < 20:
                time.sleep(30)
        r = get_npm_score(x["name"], "latest")
        v = r.get("verdict", "?")
        cl = x["event_cluster"]
        is_pred = v in ("MALICIOUS", "HIGH_RISK", "SUSPICIOUS")
        if v in ("ERROR", "UNKNOWN", "PARSE_ERROR"):
            err += 1; by_cluster[cl][2] += 1
        elif is_pred:
            tp += 1; by_cluster[cl][0] += 1
        else:
            fn += 1; by_cluster[cl][1] += 1
        results.append({"name": x["name"], "cluster": cl,
                        "verdict": v, "score": r.get("score")})
        time.sleep(0.7)

    q1 = get_quota()
    n = tp + fn
    print(f"\n=== Socket multievent ===", flush=True)
    print(f"  TP={tp} FN={fn} ERR={err} n={n} Recall={tp/max(1,n):.4f}", flush=True)
    print(f"  quota: {q0.get('quota')} -> {q1.get('quota')}", flush=True)

    OUT.write_text(json.dumps({
        "tool": "Socket multievent",
        "results": results,
        "tp": tp, "fn": fn, "err": err, "n": n,
        "recall": round(tp / max(1, n), 4),
        "by_cluster": {k: v for k, v in by_cluster.items()},
    }, ensure_ascii=False, indent=2), encoding="utf-8")
    print("saved.", flush=True)


if __name__ == "__main__":
    main()
