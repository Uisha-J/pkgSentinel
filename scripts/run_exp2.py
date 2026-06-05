# -*- coding: utf-8 -*-
"""실험2 — 다중 사건 zero-day 재측정 (출하 엔진, claude).
Shai-Hulud / Mini Shai-Hulud / TrapDoor 캠페인별 탐지율(recall). ASCII 출력."""
import json, os, sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DATA = ROOT / "scripts" / "eval_real_data"
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "scripts"))

import eval_prod as E  # monkeypatch + evaluate 재사용
import pkgsentinel.pipeline as P
P.check = E._patched_check
P.extract_all = E._patched_extract_all

CAMPAIGNS = [
    ("Shai-Hulud",      "shai_hulud_dd_fixtures.json"),
    ("Mini Shai-Hulud", "_exp2_mini.json"),
    ("TrapDoor",        "_exp2_trapdoor.json"),
]

allout = {}
for camp, fn in CAMPAIGNS:
    fx = json.load(open(DATA / fn, encoding="utf-8"))
    fixtures = fx["fixtures"] if isinstance(fx, dict) else fx
    res = []
    det = 0
    for i, meta in enumerate(fixtures, 1):
        r = E.evaluate(meta)
        res.append(r)
        if E.is_detected(r["verdict"]):
            det += 1
        print(f"[{camp}] {i}/{len(fixtures)} {r['name'][:34]:34s} -> {r['verdict']:13s} (det={det})", flush=True)
        json.dump({"campaign": camp, "results": res}, open(DATA / f"results_exp2_{camp.replace(' ','_')}.json", "w"), indent=1)
    analyzable = [r for r in res if not r["verdict"].startswith("ERR") and r["verdict"] != "CANNOT_ANALYZE"]
    err = [r for r in res if r["verdict"].startswith("ERR")]
    recall = det / len(analyzable) if analyzable else 0
    recall_total = det / len(fixtures) if fixtures else 0
    allout[camp] = {"n": len(fixtures), "analyzable": len(analyzable), "detected": det,
                    "err": len(err), "recall_analyzable": round(recall, 4),
                    "recall_total": round(recall_total, 4)}
    print(f"\n=== {camp}: detected {det}/{len(fixtures)} (analyzable {len(analyzable)}) "
          f"recall={recall:.3f} ===\n", flush=True)

json.dump(allout, open(DATA / "results_exp2_summary.json", "w"), indent=2)
print("EXP2 SUMMARY:", json.dumps(allout))
print("DONE")
