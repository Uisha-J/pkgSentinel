"""Multi-event 일반화 측정용 stratified sample 다운로드 (DataDog compromised_lib).

Sampling Protocol (재현 가능):
  모집단     : DataDog compromised_lib npm (Shai-Hulud 제외)
  Stratum    : 사건 별 (scope prefix: @tanstack, @voiceflow 등)
  포함 기준   : cluster size >= 10
  Sample/str : min(10, cluster_size)
  선택 방법   : 패키지명 사전순 정렬 후 앞 N개 (deterministic)
  목적       : multi-event 일반화 능력 측정

산출:
  scripts/eval_real_data/cache/multievent/<file>.zip (zip+password 'infected')
  scripts/eval_real_data/multievent_fixtures.json
"""
from __future__ import annotations

import json
import re
import time
import urllib.parse
import urllib.request
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CACHE_NPM_OSV = ROOT / "src" / "pkgsentinel" / "knowledge" / "cache" / "osv_npm.json"
OUT_DIR = ROOT / "scripts" / "eval_real_data" / "cache" / "multievent"
OUT_FX = ROOT / "scripts" / "eval_real_data" / "multievent_fixtures.json"

REPO = "DataDog/malicious-software-packages-dataset"
TREE_URL = f"https://api.github.com/repos/{REPO}/git/trees/main?recursive=1"
RAW_BASE = f"https://raw.githubusercontent.com/{REPO}/main"

# Sampling protocol 상수
CLUSTER_MIN_SIZE = 10
SAMPLE_PER_STRATUM = 10


def _http(url: str, timeout: int = 60) -> bytes | None:
    try:
        req = urllib.request.Request(url, headers={
            "User-Agent": "pkgsentinel-research/1.0",
        })
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.read()
    except Exception as e:
        print(f"  fetch err: {e}")
        return None


def cluster_of(name: str) -> str:
    """scope prefix 또는 첫 단어로 cluster 식별."""
    if name.startswith("@"):
        return name.split("/")[0]
    return re.split(r"[-_]", name, 1)[0]


def main():
    # 1) Shai-Hulud 패키지 (제외 대상)
    print("Loading Shai-Hulud exclusion list...")
    with CACHE_NPM_OSV.open("rb") as f:
        osv = json.loads(f.read().decode("utf-8"))
    shai_names = set()
    for a in osv:
        txt = (str(a.get("summary", "")) + " " + str(a.get("details", ""))).lower()
        if "shai-hulud" in txt:
            for ap in a.get("affected_packages", []):
                n = ap if isinstance(ap, str) else (ap.get("name", "") if isinstance(ap, dict) else "")
                if n:
                    shai_names.add(n)
    print(f"  Shai-Hulud 제외 대상: {len(shai_names)}")

    # 2) DataDog tree → compromised_lib npm 패키지 + path
    print("Fetching DataDog tree...")
    tree_data = _http(TREE_URL)
    if not tree_data:
        print("ERROR: tree fetch failed"); return
    tree = json.loads(tree_data.decode("utf-8")).get("tree", [])

    name_to_path: dict[str, str] = {}
    for x in tree:
        p = x.get("path", "")
        if not p.endswith(".zip"):
            continue
        if not p.startswith("samples/npm/compromised_lib/"):
            continue
        parts = p.split("/")
        if len(parts) < 4:
            continue
        raw = parts[3]
        if raw.startswith("@"):
            idx = raw.find("@", 1)
            name = "@" + raw[1:idx] + "/" + raw[idx + 1:] if idx > 0 else raw
        else:
            name = raw
        # 첫 version 만 (deterministic — 정렬 후 첫번째)
        if name not in name_to_path or p < name_to_path[name]:
            name_to_path[name] = p

    # 3) Shai-Hulud 제외
    non_shai = {n: p for n, p in name_to_path.items() if n not in shai_names}
    print(f"  compromised_lib npm 총: {len(name_to_path)}")
    print(f"  Shai-Hulud 제외 후:    {len(non_shai)}")

    # 4) cluster 별 grouping
    clusters: dict[str, list[str]] = defaultdict(list)
    for name in non_shai:
        clusters[cluster_of(name)].append(name)

    # 5) cluster size >= 10 인 것만, 각 정렬 후 앞 10개
    print(f"\n=== Stratified sampling (cluster >= {CLUSTER_MIN_SIZE}) ===")
    selected: list[tuple[str, str, str]] = []  # (cluster, name, path)
    for cl, names in sorted(clusters.items(),
                            key=lambda kv: -len(kv[1])):
        if len(names) < CLUSTER_MIN_SIZE:
            continue
        chosen = sorted(names)[:SAMPLE_PER_STRATUM]
        print(f"  {cl:40s} cluster_size={len(names):>3} → 선택 {len(chosen)}")
        for n in chosen:
            selected.append((cl, n, non_shai[n]))

    print(f"\n  선택된 stratum 수: {len(set(c for c,_,_ in selected))}")
    print(f"  총 sample: {len(selected)}")

    # 6) 다운로드
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    fixtures = []
    ok = 0
    for i, (cl, name, path) in enumerate(selected, 1):
        url = f"{RAW_BASE}/{urllib.parse.quote(path)}"
        fname = path.split("/")[-1]
        version = path.split("/")[-2]
        out = OUT_DIR / fname
        if out.exists() and out.stat().st_size > 100:
            ok += 1
        else:
            data = _http(url, timeout=60)
            if not (data and len(data) > 100):
                print(f"  [{i:>3}/{len(selected)}] {name:45s} FAIL")
                continue
            out.write_bytes(data)
            ok += 1
        fixtures.append({
            "name": name,
            "ecosystem": "npm",
            "version": version,
            "label": "malicious",
            "source": "datadog/multievent",
            "event_cluster": cl,
            "archive_path": str(out.relative_to(ROOT / "scripts" / "eval_real_data")),
            "archive_format": "zip+password",
            "archive_inner": None,
            "_origin": path,
        })
        if i % 20 == 0:
            print(f"  [{i:>3}/{len(selected)}] downloaded ok={ok}")
        time.sleep(0.2)

    print(f"\n=== 결과 ===")
    print(f"  OK: {ok}/{len(selected)}")

    manifest = {
        "fixtures": fixtures,
        "generated_at": "2026-05-29",
        "sampling_protocol": {
            "population": "DataDog compromised_lib npm (Shai-Hulud excluded)",
            "stratum": "event cluster (scope prefix)",
            "inclusion_criterion": f"cluster_size >= {CLUSTER_MIN_SIZE}",
            "sample_per_stratum": f"min({SAMPLE_PER_STRATUM}, cluster_size)",
            "selection": "deterministic — sorted by name, first N",
            "purpose": "multi-event generalization measurement",
        },
        "shai_hulud_excluded": len(shai_names),
        "n_strata": len(set(c for c, _, _ in selected)),
        "n_samples": len(fixtures),
    }
    OUT_FX.write_text(json.dumps(manifest, ensure_ascii=False, indent=2),
                      encoding="utf-8")
    print(f"\nFixture manifest: {OUT_FX}")


if __name__ == "__main__":
    main()
