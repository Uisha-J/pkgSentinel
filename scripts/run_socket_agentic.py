"""Socket 측정 — agentic npm 50개 (Task C).

각 패키지를 정상이라 가정 (label=benign). Socket verdict 가 어떻게 나오는지.
FPR 측정.
"""
from __future__ import annotations

import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from eval_compare_socket import get_npm_score, get_quota

ROOT = Path(__file__).resolve().parent.parent
SOURCE = ROOT / "scripts" / "eval_real_data" / "agentic_packages.json"
OUT = ROOT / "scripts" / "eval_real_data" / "results_socket_agentic_npm.json"


def main():
    pkgs = json.loads(SOURCE.read_text(encoding="utf-8"))["npm_packages"]
    print(f"=== Socket on agentic npm ({len(pkgs)}) ===")
    q0 = get_quota()
    print(f"  starting quota: {q0.get('quota')}")

    results = []
    fp = tn = err = 0
    by_verdict = {}
    for i, name in enumerate(pkgs, 1):
        # quota safety
        if i % 20 == 0:
            q = get_quota()
            rem = q.get("quota", 0)
            if rem < 30:
                print(f"  ⏸ quota {rem} < 30, 30초 대기")
                time.sleep(30)

        r = get_npm_score(name, "latest")
        item = {
            "name": name, "ecosystem": "npm",
            "label": "benign",
            "source": "agentic_dataset",
            "verdict": r.get("verdict"),
            "score": r.get("score"),
            "critical": r.get("critical_issues"),
            "high": r.get("high_issues"),
        }
        results.append(item)
        v = r.get("verdict", "")
        by_verdict[v] = by_verdict.get(v, 0) + 1
        if v in ("ERROR", "PARSE_ERROR", "UNKNOWN"):
            err += 1
        elif v in ("MALICIOUS", "HIGH_RISK", "SUSPICIOUS"):
            fp += 1
        else:
            tn += 1
        print(f"  [{i:>2}/{len(pkgs)}] {name:42s} → {v:12s} score={r.get('score')}")
        time.sleep(1.0)

    q1 = get_quota()
    print(f"\n=== 결과 ===")
    print(f"  by verdict: {by_verdict}")
    print(f"  FP={fp}  TN={tn}  ERR={err}")
    n = fp + tn
    fpr = fp/n if n else 0
    print(f"  FPR = {fpr:.4f} ({fp}/{n})")
    print(f"  quota: {q0.get('quota')} → {q1.get('quota')}")

    out_data = {
        "tool": "Socket.dev API on agentic dataset",
        "results": results,
        "by_verdict": by_verdict,
        "fpr": round(fpr, 4),
        "fp": fp, "tn": tn, "err": err, "n": n,
        "quota_start": q0, "quota_end": q1,
    }
    OUT.write_text(json.dumps(out_data, ensure_ascii=False, indent=2),
                   encoding="utf-8")
    print(f"  saved: {OUT}")


if __name__ == "__main__":
    main()
