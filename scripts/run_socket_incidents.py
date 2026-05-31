"""사건별 Socket.dev 측정 (정확한 악성 버전). zero-day 다중 사건 비교 보강."""
import sys, json, time
from collections import defaultdict
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
from eval_compare_socket import get_npm_score, get_quota

ROOT = Path(__file__).resolve().parent.parent
DATA = ROOT / "scripts" / "eval_real_data"

# 사건별 fixtures
SOURCES = [
    ("shai_hulud", DATA / "shai_hulud_dd_fixtures.json", "Shai-Hulud (2025-09)"),
    ("incidents", DATA / "incidents_fixtures.json", None),  # mini + trapdoor
]
MAL = ("MALICIOUS", "HIGH_RISK", "SUSPICIOUS")
ERRV = ("ERROR", "UNKNOWN", "PARSE_ERROR", "")


def main():
    q0 = get_quota(); print(f"quota start: {q0.get('quota')}", flush=True)
    by = defaultdict(lambda: {"tp": 0, "clean": 0, "err": 0, "label": ""})
    rows = []
    items = []
    for key, fp, label in SOURCES:
        fx = json.loads(fp.read_text(encoding="utf-8"))["fixtures"]
        for x in fx:
            ik = x.get("incident_key") or key
            lbl = x.get("incident") or label or key
            items.append((ik, lbl, x["name"], x.get("version", "latest")))

    print(f"총 {len(items)} 패키지 Socket 조회", flush=True)
    for i, (ik, lbl, name, ver) in enumerate(items, 1):
        r = get_npm_score(name, ver)
        v = r.get("verdict", "?")
        by[ik]["label"] = lbl
        if v in ERRV:
            by[ik]["err"] += 1
        elif v in MAL:
            by[ik]["tp"] += 1
        else:
            by[ik]["clean"] += 1
        rows.append({"incident": ik, "name": name, "version": ver, "verdict": v,
                     "score": r.get("score")})
        if i % 40 == 0:
            print(f"  [{i}/{len(items)}] quota={get_quota().get('quota')}", flush=True)
        time.sleep(0.4)

    print("\n=== Socket 사건별 ===", flush=True)
    for ik, d in by.items():
        n_valid = d["tp"] + d["clean"]
        rec = d["tp"] / n_valid if n_valid else 0
        print(f"  {d['label']}", flush=True)
        print(f"    탐지={d['tp']} clean(미탐)={d['clean']} ERROR(unpublish등)={d['err']} "
              f"| 유효n={n_valid} recall={rec:.3f}", flush=True)

    (DATA / "results_socket_incidents.json").write_text(
        json.dumps({"by_incident": {k: dict(v) for k, v in by.items()}, "rows": rows},
                   ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"\nquota end: {get_quota().get('quota')}  saved.", flush=True)


if __name__ == "__main__":
    main()
