"""명명 사건별 샘플 다운로드 (DataDog) — 다중 사건 zero-day 비교용.

사건:
  Mini Shai-Hulud (2026-05, TeamPCP) : @mistralai/@squawk/@uipath/@tanstack 등
  TrapDoor        (2026-05)          : 지갑/solana/eth 자격증명 탈취 캠페인

산출: cache/incidents/<incident>/<file>.zip + incidents_fixtures.json
"""
from __future__ import annotations
import json, re, time, urllib.parse, urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "scripts" / "eval_real_data" / "cache" / "incidents"
FX = ROOT / "scripts" / "eval_real_data" / "incidents_fixtures.json"
REPO = "DataDog/malicious-software-packages-dataset"
TREE = f"https://api.github.com/repos/{REPO}/git/trees/main?recursive=1"
RAW = f"https://raw.githubusercontent.com/{REPO}/main"

INCIDENTS = {
    "mini_shai_hulud": dict(
        label="Mini Shai-Hulud (2026-05, TeamPCP)",
        pat=re.compile(r"^(@?mistralai|@?squawk|@?uipath|@?tanstack|guardrails-ai)", re.I),
        sample=40),
    "trapdoor": dict(
        label="TrapDoor (2026-05, wallet/crypto stealer)",
        pat=re.compile(r"wallet|solana|eth-security|raydium|@ton-|frontend-clients", re.I),
        sample=46),
}


def http(url, timeout=60):
    req = urllib.request.Request(url, headers={"User-Agent": "pkgsentinel/1.0"})
    return urllib.request.urlopen(req, timeout=timeout).read()


def main():
    print("Fetching DataDog tree...")
    tree = json.loads(http(TREE).decode())["tree"]
    zips = [x["path"] for x in tree if x["path"].endswith(".zip")
            and x["path"].startswith("samples/npm/")]

    # 사건별 패키지 -> 첫 경로
    OUT.mkdir(parents=True, exist_ok=True)
    fixtures = []
    for key, info in INCIDENTS.items():
        name_to_path = {}
        for p in zips:
            parts = p.split("/")
            if len(parts) < 4:
                continue
            raw = parts[3]
            if not info["pat"].search(raw):
                continue
            # 스코프 복원
            if raw.startswith("@"):
                idx = raw.find("@", 1)
                nm = "@" + raw[1:idx] + "/" + raw[idx+1:] if idx > 0 else raw
            else:
                nm = raw
            if nm not in name_to_path or p < name_to_path[nm]:
                name_to_path[nm] = p
        chosen = sorted(name_to_path)[: info["sample"]]
        d = OUT / key
        d.mkdir(parents=True, exist_ok=True)
        ok = 0
        for nm in chosen:
            path = name_to_path[nm]
            fname = path.split("/")[-1]
            ver = path.split("/")[-2]
            outp = d / fname
            if not (outp.exists() and outp.stat().st_size > 100):
                try:
                    data = http(f"{RAW}/{urllib.parse.quote(path)}")
                except Exception as e:
                    print(f"  FAIL {nm}: {e}"); continue
                if not data or len(data) < 100:
                    continue
                outp.write_bytes(data)
            ok += 1
            fixtures.append({
                "name": nm, "ecosystem": "npm", "version": ver,
                "label": "malicious", "source": f"datadog/{key}",
                "incident": info["label"], "incident_key": key,
                "archive_path": str(outp.relative_to(ROOT / "scripts" / "eval_real_data")),
                "archive_format": "zip+password", "archive_inner": None,
                "_origin": path,
            })
            time.sleep(0.15)
        print(f"  {info['label']}: {ok}/{len(chosen)} downloaded")

    FX.write_text(json.dumps({"fixtures": fixtures, "generated_at": "2026-05-30",
        "incidents": {k: v["label"] for k, v in INCIDENTS.items()},
        "n": len(fixtures)}, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"\nfixtures: {FX}  (총 {len(fixtures)})")


if __name__ == "__main__":
    main()
