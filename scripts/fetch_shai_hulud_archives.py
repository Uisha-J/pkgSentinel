"""Shai-Hulud 187 패키지 archive 확보 시도.

소스 (우선순위):
  1. npm registry 직접 (대부분 unpublish → 실패 예상)
  2. Wayback Machine (web.archive.org) snapshot
  3. (수동) 보안 회사 dataset (Phylum/Sonatype/JFrog repo 탐색은 별도 단계)

산출:
  - cache/shai_hulud/<name>-<version>.tgz (확보된 archive)
  - shai_hulud_fetch_report.json (성공/실패 보고서)

ground truth list:
  OSV cache 에서 Shai-Hulud 명시 advisory 의 affected_packages 추출
  → DataDog 와의 intersection 제외 (이미 측정함)
  → disjoint 187개 = bias-free testset 후보
"""
from __future__ import annotations

import argparse
import json
import time
import urllib.parse
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CACHE_NPM_OSV = ROOT / "src" / "pkgsentinel" / "knowledge" / "cache" / "osv_npm.json"
FIXTURES = ROOT / "scripts" / "eval_real_data" / "fixtures.json"
OUT_DIR = ROOT / "scripts" / "eval_real_data" / "cache" / "shai_hulud"
REPORT = ROOT / "scripts" / "eval_real_data" / "shai_hulud_fetch_report.json"


USER_AGENT = (
    "pkgsentinel-research/1.0 (capstone; "
    "academic Shai-Hulud reproduction; do-not-distribute)"
)


def _http_get(url: str, timeout: int = 30) -> bytes | None:
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.read()
    except Exception as e:
        return None


def _http_get_json(url: str, timeout: int = 30) -> dict | None:
    b = _http_get(url, timeout)
    if not b:
        return None
    try:
        return json.loads(b.decode("utf-8"))
    except Exception:
        return None


# ─────────────── 1) Shai-Hulud 187 list 추출 ───────────────

def load_shai_hulud_disjoint_list() -> list[dict]:
    """OSV Shai-Hulud advisory affected_packages - DataDog compromised_lib intersection."""
    with CACHE_NPM_OSV.open("rb") as f:
        npm = json.loads(f.read().decode("utf-8"))
    shai_pkgs = {}  # name -> [versions]
    for a in npm:
        txt = (str(a.get("summary", "")) + " " + str(a.get("details", ""))).lower()
        if "shai-hulud" not in txt and "shai hulud" not in txt:
            continue
        affected_versions = a.get("affected_versions") or []
        for ap in a.get("affected_packages", []):
            name = ap if isinstance(ap, str) else (ap.get("name", "") if isinstance(ap, dict) else "")
            if not name:
                continue
            shai_pkgs.setdefault(name, set()).update(affected_versions or ["unknown"])

    # DataDog compromised_lib (npm) 와 disjoint
    with FIXTURES.open("rb") as f:
        fx = json.loads(f.read().decode("utf-8"))["fixtures"]
    dd_names = {x["name"] for x in fx
                if x.get("ecosystem") == "npm"
                and x.get("source") == "datadog/compromised_lib"}

    out = []
    for name, versions in shai_pkgs.items():
        if name in dd_names:
            continue
        out.append({"name": name,
                    "versions": sorted(v for v in versions if v != "unknown")})
    return out


# ─────────────── 2) npm registry 직접 시도 ───────────────

def try_npm_registry(name: str, version: str) -> tuple[str, bytes | None]:
    """현재 registry 에 archive 가 살아 있나? (대부분 unpublish 됨)."""
    safe = urllib.parse.quote(name, safe="@/")
    meta_url = f"https://registry.npmjs.org/{safe}"
    meta = _http_get_json(meta_url, timeout=15)
    if not meta:
        return ("registry_404", None)
    versions = meta.get("versions") or {}
    if version not in versions:
        return ("version_unpublished", None)
    tarball = versions[version].get("dist", {}).get("tarball")
    if not tarball:
        return ("no_tarball_url", None)
    data = _http_get(tarball, timeout=60)
    if data:
        return ("registry_ok", data)
    return ("tarball_fetch_failed", None)


# ─────────────── 3) Wayback Machine 시도 ───────────────

def try_jsdelivr(name: str, version: str) -> tuple[str, bytes | None]:
    """jsdelivr CDN — npm mirror. 일부 unpublish 패키지가 살아 있을 수 있음."""
    safe = urllib.parse.quote(name, safe="@/")
    # jsdelivr 는 폴더 listing 만 제공 — package.json 만이라도 받아오면 코드 분석 가능
    url = f"https://cdn.jsdelivr.net/npm/{safe}@{version}/package.json"
    data = _http_get(url, timeout=20)
    if data and len(data) > 10:
        # package.json 이라도 받았다면 source 도 시도
        # 일단 package.json 만으로는 부족하지만 존재 확인
        return ("jsdelivr_metadata_ok", data)
    return ("jsdelivr_missing", None)


def try_unpkg(name: str, version: str) -> tuple[str, bytes | None]:
    """unpkg.com — 또 다른 npm CDN mirror."""
    safe = urllib.parse.quote(name, safe="@/")
    url = f"https://unpkg.com/{safe}@{version}/package.json"
    data = _http_get(url, timeout=20)
    if data and len(data) > 10:
        return ("unpkg_metadata_ok", data)
    return ("unpkg_missing", None)


def try_wayback_machine(name: str, version: str,
                        target_ts: str = "20250920") -> tuple[str, bytes | None]:
    """Wayback Machine 에서 사건 시점 (2025-09) 의 snapshot tarball 시도.

    절차:
      1) registry metadata page 의 archived snapshot 찾기
      2) 그 snapshot 에서 tarball URL 추출 (현재 우회 — npm dist URL 패턴 직접 시도)
    """
    safe = urllib.parse.quote(name, safe="@/")
    # npm dist tarball URL 패턴
    bare = name.split("/", 1)[-1] if name.startswith("@") else name
    tarball_url = f"https://registry.npmjs.org/{safe}/-/{bare}-{version}.tgz"

    # availability check
    avail = (f"https://archive.org/wayback/available?"
             f"url={urllib.parse.quote(tarball_url)}&timestamp={target_ts}")
    j = _http_get_json(avail, timeout=20)
    if not j:
        return ("wayback_no_response", None)
    snap = (j.get("archived_snapshots") or {}).get("closest")
    if not snap or not snap.get("available"):
        return ("wayback_no_snapshot", None)

    snap_url = snap.get("url", "")
    if not snap_url:
        return ("wayback_no_url", None)

    # snapshot 가져오기 (302 redirect 따라감)
    data = _http_get(snap_url, timeout=90)
    if data and len(data) > 100:
        return (f"wayback_ok ({snap.get('timestamp','?')})", data)
    return ("wayback_fetch_failed", None)


# ─────────────── 메인 ───────────────

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--limit", type=int, default=0,
                    help="앞 N 개만 시도 (테스트용, 0=전체)")
    ap.add_argument("--skip-registry", action="store_true",
                    help="registry 직접 시도 생략 (대부분 실패하므로)")
    ap.add_argument("--sleep", type=float, default=1.0,
                    help="Wayback 호출 간 sleep (rate limit)")
    args = ap.parse_args()

    print("=== Shai-Hulud 187 archive 확보 시도 ===")
    print(f"OSV cache: {CACHE_NPM_OSV}")
    print()

    pkgs = load_shai_hulud_disjoint_list()
    print(f"OSV Shai-Hulud 영향 (DataDog 와 disjoint): {len(pkgs)} 패키지")
    if args.limit:
        pkgs = pkgs[:args.limit]
        print(f"  → 앞 {args.limit}개만 시도 (테스트)")

    OUT_DIR.mkdir(parents=True, exist_ok=True)

    report = []
    counts = {"registry_ok": 0, "wayback_ok": 0,
              "jsdelivr_ok": 0, "unpkg_ok": 0,
              "all_missing": 0, "skipped": 0}

    for i, p in enumerate(pkgs, 1):
        name = p["name"]
        versions = p["versions"] or ["unknown"]
        if "unknown" in versions and len(versions) == 1:
            # affected_versions 모르면 latest 시도
            versions = ["latest"]

        # 첫 affected version 만 시도 (representative)
        version = versions[0]

        # 이미 받은 거 skip
        safe_name = name.replace("/", "__").replace("@", "_")
        out_path = OUT_DIR / f"{safe_name}-{version}.tgz"
        if out_path.exists() and out_path.stat().st_size > 100:
            counts["skipped"] += 1
            report.append({"name": name, "version": version,
                           "status": "already_have",
                           "size": out_path.stat().st_size})
            print(f"  [{i:3d}/{len(pkgs)}] {name:45s} v{version:15s}  "
                  f"already have")
            continue

        # 1) registry
        status_reg = "skipped"
        data = None
        if not args.skip_registry:
            status_reg, data = try_npm_registry(name, version)
            if data:
                out_path.write_bytes(data)
                counts["registry_ok"] += 1
                print(f"  [{i:3d}/{len(pkgs)}] {name:45s} v{version:15s}  "
                      f"REG OK ({len(data)} bytes)")
                report.append({"name": name, "version": version,
                               "status": "registry_ok",
                               "size": len(data)})
                time.sleep(0.3)
                continue
            pass  # registry 실패는 all_missing 에서 카운트

        # 2) Wayback
        status_wb, data = try_wayback_machine(name, version)
        if data:
            out_path.write_bytes(data)
            counts["wayback_ok"] += 1
            print(f"  [{i:3d}/{len(pkgs)}] {name:45s} v{version:15s}  "
                  f"WAYBACK OK ({len(data)} bytes) reg={status_reg}")
            report.append({"name": name, "version": version,
                           "status": "wayback_ok",
                           "size": len(data)})
            time.sleep(args.sleep)
            continue

        # 3) jsdelivr CDN
        status_jsd, data = try_jsdelivr(name, version)
        if data:
            # package.json 만 받아 와서 metadata 보존 (full tarball 은 아님)
            (OUT_DIR / f"{safe_name}-{version}.package.json").write_bytes(data)
            counts["jsdelivr_ok"] += 1
            print(f"  [{i:3d}/{len(pkgs)}] {name:45s} v{version:15s}  "
                  f"JSDELIVR metadata only ({len(data)} bytes)")
            report.append({"name": name, "version": version,
                           "status": "jsdelivr_metadata_only",
                           "size": len(data)})
            time.sleep(args.sleep)
            continue

        # 4) unpkg
        status_unp, data = try_unpkg(name, version)
        if data:
            (OUT_DIR / f"{safe_name}-{version}.package.json").write_bytes(data)
            counts["unpkg_ok"] += 1
            print(f"  [{i:3d}/{len(pkgs)}] {name:45s} v{version:15s}  "
                  f"UNPKG metadata only ({len(data)} bytes)")
            report.append({"name": name, "version": version,
                           "status": "unpkg_metadata_only",
                           "size": len(data)})
            time.sleep(args.sleep)
            continue

        counts["all_missing"] += 1
        print(f"  [{i:3d}/{len(pkgs)}] {name:45s} v{version:15s}  "
              f"ALL MISSING ({status_reg} / {status_wb} / {status_jsd} / {status_unp})")
        report.append({"name": name, "version": version,
                       "status": "missing",
                       "registry_status": status_reg,
                       "wayback_status": status_wb,
                       "jsdelivr_status": status_jsd,
                       "unpkg_status": status_unp})

        time.sleep(args.sleep)

    print()
    print("=== 결과 ===")
    total_ok = counts["registry_ok"] + counts["wayback_ok"] + counts["skipped"]
    print(f"  registry OK   : {counts['registry_ok']:>3}")
    print(f"  wayback  OK   : {counts['wayback_ok']:>3}")
    print(f"  jsdelivr OK   : {counts['jsdelivr_ok']:>3}  (metadata only)")
    print(f"  unpkg    OK   : {counts['unpkg_ok']:>3}  (metadata only)")
    print(f"  already have  : {counts['skipped']:>3}")
    print(f"  all  missing  : {counts['all_missing']:>3}")
    print(f"  ─────────────")
    full_ok = counts['registry_ok'] + counts['wayback_ok'] + counts['skipped']
    print(f"  TOTAL OK (full archive) : {full_ok}/{len(pkgs)} "
          f"({full_ok/max(1,len(pkgs))*100:.1f}%)")
    meta_ok = counts['jsdelivr_ok'] + counts['unpkg_ok']
    print(f"  TOTAL OK (metadata only): {meta_ok}/{len(pkgs)} "
          f"({meta_ok/max(1,len(pkgs))*100:.1f}%)")

    # 보고서 저장
    REPORT.write_text(json.dumps({
        "summary": {**counts,
                    "total_attempted": len(pkgs),
                    "total_ok": total_ok,
                    "success_rate": round(total_ok/max(1,len(pkgs)), 4)},
        "items": report,
    }, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"\nReport: {REPORT}")
    print(f"Cache:  {OUT_DIR}")


if __name__ == "__main__":
    main()
