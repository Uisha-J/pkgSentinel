"""사건별 njsscan(JS SAST) + OSV 커버리지 측정 — 다중 사건 zero-day 비교용."""
from __future__ import annotations
import json, subprocess, tempfile, zipfile, urllib.request, urllib.parse
from collections import defaultdict
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor

ROOT = Path(__file__).resolve().parent.parent
FX = ROOT / "scripts" / "eval_real_data" / "incidents_fixtures.json"
OUT = ROOT / "scripts" / "eval_real_data" / "results_incidents_jssast_osv.json"


def unpack(zp, dest):
    with zipfile.ZipFile(zp, "r") as z:
        z.setpassword(b"infected"); z.extractall(dest)


def njsscan(target) -> bool:
    """finding>=1 → 탐지(True)."""
    try:
        r = subprocess.run(["njsscan", "--json", str(target)],
                           capture_output=True, text=True, timeout=120)
        out = json.loads(r.stdout) if r.stdout else {}
        total = 0
        for sec in ("nodejs", "templates"):
            for _rule, info in (out.get(sec) or {}).items():
                total += max(1, len(info.get("files", []))) if isinstance(info, dict) else 1
        return total >= 1
    except Exception:
        return False


def osv_hit(name: str) -> bool:
    """OSV 현재 등재 여부 (live API)."""
    url = "https://api.osv.dev/v1/query"
    body = json.dumps({"package": {"name": name, "ecosystem": "npm"}}).encode()
    try:
        req = urllib.request.Request(url, data=body,
            headers={"Content-Type": "application/json", "User-Agent": "pk/1.0"})
        with urllib.request.urlopen(req, timeout=15) as r:
            d = json.loads(r.read())
            return bool(d.get("vulns"))
    except Exception:
        return False


def main():
    fx = json.loads(FX.read_text(encoding="utf-8"))["fixtures"]
    print(f"=== 사건별 njsscan + OSV — {len(fx)} pkgs ===", flush=True)

    # njsscan (순차 — unpack)
    nj = {}
    for i, item in enumerate(fx, 1):
        zp = ROOT / "scripts" / "eval_real_data" / item["archive_path"]
        if not zp.exists():
            nj[item["name"]] = None; continue
        with tempfile.TemporaryDirectory() as td:
            try:
                unpack(zp, Path(td)); nj[item["name"]] = njsscan(Path(td))
            except Exception:
                nj[item["name"]] = None
        if i % 20 == 0:
            print(f"  njsscan {i}/{len(fx)}", flush=True)

    # OSV (병렬)
    print("  OSV 조회...", flush=True)
    with ThreadPoolExecutor(max_workers=10) as ex:
        osvs = dict(zip([x["name"] for x in fx],
                        ex.map(lambda x: osv_hit(x["name"]), fx)))

    # 사건별 집계
    by = defaultdict(lambda: {"n": 0, "njsscan": 0, "osv": 0, "label": ""})
    for item in fx:
        k = item["incident_key"]; nm = item["name"]
        by[k]["label"] = item["incident"]; by[k]["n"] += 1
        if nj.get(nm): by[k]["njsscan"] += 1
        if osvs.get(nm): by[k]["osv"] += 1

    print("\n=== 결과 (사건별) ===", flush=True)
    for k, v in by.items():
        n = v["n"]
        print(f"  {v['label']}", flush=True)
        print(f"    n={n}  njsscan={v['njsscan']} ({100*v['njsscan']/n:.1f}%)  "
              f"OSV={v['osv']} ({100*v['osv']/n:.1f}%)", flush=True)

    OUT.write_text(json.dumps({k: dict(v) for k, v in by.items()},
                              ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"\nsaved: {OUT}", flush=True)


if __name__ == "__main__":
    main()
