"""Agentic 악성 패키지 archive 다운로드 (DataDog repo).

OSV strict agentic MAL (npm 63) 중 DataDog repo 에 있는 34개 다운로드.

산출:
  scripts/eval_real_data/cache/agentic_mal/<file>.zip (zip+password 'infected')
  scripts/eval_real_data/agentic_malicious_fixtures.json (측정용)
"""
from __future__ import annotations

import json
import re
import time
import urllib.parse
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CACHE_NPM_OSV = ROOT / "src" / "pkgsentinel" / "knowledge" / "cache" / "osv_npm.json"
OUT_DIR = ROOT / "scripts" / "eval_real_data" / "cache" / "agentic_mal"
OUT_FX = ROOT / "scripts" / "eval_real_data" / "agentic_malicious_fixtures.json"

REPO = "DataDog/malicious-software-packages-dataset"
TREE_URL = f"https://api.github.com/repos/{REPO}/git/trees/main?recursive=1"
RAW_BASE = f"https://raw.githubusercontent.com/{REPO}/main"

STRICT_PAT = re.compile(
    r"^(@modelcontextprotocol/|@langchain/|@llamaindex/|@ai-sdk/|@anthropic-ai/|@openai/)|"
    r"^(langchain|langgraph|llama[-_]?index|crewai|autogen|mcp[-_]|openai[-_]agents?|"
    r"ai[-_]agent|llm[-_]?agent|praisonai|haystack[-_]ai)",
    re.IGNORECASE,
)


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


def is_agentic(name: str) -> bool:
    return (STRICT_PAT.search(name) is not None
            or name.endswith("-agent")
            or "-mcp-" in name
            or name.endswith("-mcp-server"))


def main():
    # 1) OSV agentic MAL list
    with CACHE_NPM_OSV.open("rb") as f:
        npm_osv = json.loads(f.read().decode("utf-8"))
    agentic_mal_names = set()
    for a in npm_osv:
        aid = a.get("advisory_id", "")
        if not aid.startswith("MAL-"):
            continue
        for ap in a.get("affected_packages", []):
            name = ap if isinstance(ap, str) else (ap.get("name", "") if isinstance(ap, dict) else "")
            if name and is_agentic(name):
                agentic_mal_names.add(name)
    print(f"OSV agentic MAL (npm): {len(agentic_mal_names)}")

    # 2) DataDog tree
    print("Fetching DataDog tree...")
    tree_data = _http(TREE_URL)
    if not tree_data:
        print("ERROR: tree fetch failed"); return
    tree = json.loads(tree_data.decode("utf-8")).get("tree", [])

    name_to_paths: dict[str, list[str]] = {}
    for x in tree:
        p = x.get("path", "")
        if not p.endswith(".zip"): continue
        parts = p.split("/")
        if len(parts) < 4 or parts[0] != "samples" or parts[1] != "npm":
            continue
        raw = parts[3]
        if raw.startswith("@"):
            idx = raw.find("@", 1)
            name = "@" + raw[1:idx] + "/" + raw[idx+1:] if idx > 0 else raw
        else:
            name = raw
        name_to_paths.setdefault(name, []).append(p)

    avail = agentic_mal_names & set(name_to_paths.keys())
    missing = agentic_mal_names - set(name_to_paths.keys())
    print(f"DataDog 에서 확보 가능: {len(avail)}/{len(agentic_mal_names)}")

    # 3) 다운로드
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    fixtures = []
    ok = 0
    for i, name in enumerate(sorted(avail), 1):
        paths = name_to_paths.get(name, [])
        if not paths:
            continue
        path = sorted(paths)[0]
        url = f"{RAW_BASE}/{urllib.parse.quote(path)}"
        fname = path.split("/")[-1]
        out = OUT_DIR / fname
        if out.exists() and out.stat().st_size > 100:
            print(f"  [{i:>2}/{len(avail)}] {name:50s} already have")
            ok += 1
            version = path.split("/")[-2]
            fixtures.append({
                "name": name, "ecosystem": "npm",
                "version": version, "label": "malicious",
                "source": "datadog/agentic_malicious",
                "archive_path": str(out.relative_to(ROOT / "scripts" / "eval_real_data")),
                "archive_format": "zip+password",
                "archive_inner": None,
                "_origin": path,
            })
            continue
        data = _http(url, timeout=60)
        if data and len(data) > 100:
            out.write_bytes(data)
            ok += 1
            version = path.split("/")[-2]
            fixtures.append({
                "name": name, "ecosystem": "npm",
                "version": version, "label": "malicious",
                "source": "datadog/agentic_malicious",
                "archive_path": str(out.relative_to(ROOT / "scripts" / "eval_real_data")),
                "archive_format": "zip+password",
                "archive_inner": None,
                "_origin": path,
            })
            print(f"  [{i:>2}/{len(avail)}] {name:50s} OK ({len(data)} bytes)")
        else:
            print(f"  [{i:>2}/{len(avail)}] {name:50s} FAIL")
        time.sleep(0.3)

    print(f"\n=== 결과 ===")
    print(f"  OK: {ok}/{len(avail)}")
    print(f"  미확보 (OSV 만): {len(missing)} (Wayback 등 시도 필요)")

    manifest = {
        "fixtures": fixtures,
        "generated_at": "2026-05-28",
        "note": (
            "Task C 확장 — agentic 영역 실제 악성 패키지 (OSV MAL strict agentic). "
            "DataDog 2025-11-24 신규 업데이트 활용. recall 측정용 (manifest ON/OFF)."
        ),
        "osv_total": len(agentic_mal_names),
        "datadog_available": len(avail),
        "missing_osv_only": sorted(missing),
    }
    OUT_FX.write_text(json.dumps(manifest, ensure_ascii=False, indent=2),
                      encoding="utf-8")
    print(f"\nFixture manifest: {OUT_FX}")


if __name__ == "__main__":
    main()
