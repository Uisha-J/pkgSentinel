"""DataDog repo 2025-11-24 업데이트 활용 — Shai-Hulud 162개 archive 다운.

OSV Shai-Hulud 영향 187개 disjoint set 중 86.6% (162개) 가 DataDog 신규에 들어옴.

산출:
  scripts/eval_real_data/cache/shai_hulud_dd/<file>.zip  (zip+password 'infected')
  scripts/eval_real_data/shai_hulud_dd_fixtures.json     (측정용 fixture 매니페스트)

이후 우리 측정 pipeline 에 그대로 흘려보낼 수 있음.
"""
from __future__ import annotations

import json
import time
import urllib.parse
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CACHE_NPM_OSV = ROOT / "src" / "pkgsentinel" / "knowledge" / "cache" / "osv_npm.json"
FIXTURES = ROOT / "scripts" / "eval_real_data" / "fixtures.json"
OUT_DIR = ROOT / "scripts" / "eval_real_data" / "cache" / "shai_hulud_dd"
OUT_FX  = ROOT / "scripts" / "eval_real_data" / "shai_hulud_dd_fixtures.json"

REPO = "DataDog/malicious-software-packages-dataset"
TREE_URL = f"https://api.github.com/repos/{REPO}/git/trees/main?recursive=1"
RAW_BASE = f"https://raw.githubusercontent.com/{REPO}/main"


def _http(url: str, timeout: int = 60) -> bytes | None:
    try:
        req = urllib.request.Request(url, headers={
            "User-Agent": "pkgsentinel-research/1.0 (capstone)",
        })
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.read()
    except Exception as e:
        print(f"  fetch error: {e}")
        return None


def main():
    # 1) DataDog tree 가져오기
    print("=== DataDog repo tree fetch ===")
    data = _http(TREE_URL)
    if not data:
        print("ERROR: tree fetch failed"); return
    tree = json.loads(data.decode("utf-8")).get("tree", [])
    print(f"  total tree entries: {len(tree)}")

    # 2) compromised_lib 의 zip 파일들
    items = [x for x in tree
             if "compromised_lib" in x.get("path", "")
             and x.get("path", "").endswith(".zip")]
    print(f"  compromised_lib zips in repo: {len(items)}")

    # 3) 패키지 이름 → zip path map 구성
    name_to_paths: dict[str, list[str]] = {}
    for x in items:
        p = x["path"]
        # samples/npm/compromised_lib/<dir_name>/<version>/<file>.zip
        parts = p.split("/")
        if len(parts) < 4:
            continue
        raw = parts[3]
        if raw.startswith("@"):
            idx = raw.find("@", 1)
            if idx > 0:
                name = "@" + raw[1:idx] + "/" + raw[idx+1:]
            else:
                name = raw
        else:
            name = raw
        name_to_paths.setdefault(name, []).append(p)

    print(f"  unique packages in repo: {len(name_to_paths)}")

    # 4) OSV Shai-Hulud 영향 패키지 (disjoint 187)
    with CACHE_NPM_OSV.open("rb") as f:
        npm_osv = json.loads(f.read().decode("utf-8"))
    shai_pkgs = set()
    shai_versions: dict[str, set] = {}  # name -> versions
    for a in npm_osv:
        txt = (str(a.get("summary","")) + " " + str(a.get("details",""))).lower()
        if "shai-hulud" not in txt and "shai hulud" not in txt:
            continue
        affected_vs = a.get("affected_versions") or []
        for ap in a.get("affected_packages", []):
            name = ap if isinstance(ap, str) else (ap.get("name","") if isinstance(ap, dict) else "")
            if not name:
                continue
            shai_pkgs.add(name)
            shai_versions.setdefault(name, set()).update(affected_vs)

    with FIXTURES.open("rb") as f:
        fx_existing = json.loads(f.read().decode("utf-8"))["fixtures"]
    dd_old_names = {x["name"] for x in fx_existing
                    if x.get("ecosystem") == "npm"
                    and x.get("source") == "datadog/compromised_lib"}

    disjoint = shai_pkgs - dd_old_names
    in_repo = disjoint & set(name_to_paths.keys())
    print(f"\n=== Disjoint Shai-Hulud 187 vs DataDog 신규 1260 ===")
    print(f"  OSV Shai-Hulud 총: {len(shai_pkgs)}")
    print(f"  기존 fixture 안 : {len(shai_pkgs & dd_old_names)}")
    print(f"  disjoint        : {len(disjoint)}")
    print(f"  ★ DataDog 신규에 포함 : {len(in_repo)} (확보 가능)")
    print(f"    DataDog 에도 없음    : {len(disjoint - in_repo)} (확보 불가)")

    # 5) 다운로드
    print(f"\n=== 다운로드 시작 ({len(in_repo)} 패키지) ===")
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    fixtures_out: list[dict] = []
    ok = 0
    fail = 0
    for i, name in enumerate(sorted(in_repo), 1):
        paths = name_to_paths.get(name, [])
        if not paths:
            continue
        # 첫 (가장 작은 path 가 보통 가장 첫 version)
        path = sorted(paths)[0]
        url = f"{RAW_BASE}/{urllib.parse.quote(path)}"
        # path 의 last segment 가 filename
        fname = path.split("/")[-1]
        out_path = OUT_DIR / fname
        if out_path.exists() and out_path.stat().st_size > 100:
            print(f"  [{i:3d}/{len(in_repo)}] {name:50s}  already have")
            ok += 1
            # fixture entry 만 만들기
            version = path.split("/")[-2]
            fixtures_out.append({
                "name": name,
                "ecosystem": "npm",
                "version": version,
                "label": "malicious",
                "source": "datadog/compromised_lib_shai_hulud_disjoint",
                "archive_path": str(out_path.relative_to(ROOT / "scripts" / "eval_real_data")),
                "archive_format": "zip+password",
                "archive_inner": None,
                "_origin_repo_path": path,
            })
            continue
        data = _http(url, timeout=60)
        if data and len(data) > 100:
            out_path.write_bytes(data)
            ok += 1
            version = path.split("/")[-2]
            fixtures_out.append({
                "name": name,
                "ecosystem": "npm",
                "version": version,
                "label": "malicious",
                "source": "datadog/compromised_lib_shai_hulud_disjoint",
                "archive_path": str(out_path.relative_to(ROOT / "scripts" / "eval_real_data")),
                "archive_format": "zip+password",
                "archive_inner": None,
                "_origin_repo_path": path,
            })
            print(f"  [{i:3d}/{len(in_repo)}] {name:50s}  OK ({len(data)} bytes)")
        else:
            fail += 1
            print(f"  [{i:3d}/{len(in_repo)}] {name:50s}  FAIL")
        time.sleep(0.3)

    print(f"\n=== 결과 ===")
    print(f"  OK   : {ok}/{len(in_repo)} ({ok/max(1,len(in_repo))*100:.1f}%)")
    print(f"  FAIL : {fail}")

    # 6) fixture 매니페스트 저장
    manifest = {
        "fixtures": fixtures_out,
        "generated_at": "2026-05-28",
        "note": (
            "Shai-Hulud disjoint testset — OSV Shai-Hulud 영향 187개 중 "
            "DataDog 2025-11-24 신규에 포함된 162개를 다운. 기존 fixture 와 "
            "disjoint. measurement bias-free Shai-Hulud subset."
        ),
        "missing_packages": sorted(disjoint - in_repo),
        "missing_count": len(disjoint - in_repo),
    }
    OUT_FX.write_text(json.dumps(manifest, ensure_ascii=False, indent=2),
                      encoding="utf-8")
    print(f"\nFixtures manifest: {OUT_FX}")
    print(f"Cache dir         : {OUT_DIR}")


if __name__ == "__main__":
    main()
