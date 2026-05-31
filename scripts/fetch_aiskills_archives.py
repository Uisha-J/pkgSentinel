"""DataDog ai-skills 카테고리 archive 다운로드 (204개).

DataDog 2026-05 신규 추가된 카테고리 — Claude Code / GPT / 기타 AI agent
의 skill (확장 도구) 영역 악성 패키지.

산출:
  scripts/eval_real_data/cache/ai_skills/<file>.zip (zip+password 'infected')
  scripts/eval_real_data/ai_skills_fixtures.json
"""
from __future__ import annotations

import json
import time
import urllib.parse
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUT_DIR = ROOT / "scripts" / "eval_real_data" / "cache" / "ai_skills"
OUT_FX = ROOT / "scripts" / "eval_real_data" / "ai_skills_fixtures.json"

REPO = "DataDog/malicious-software-packages-dataset"
TREE_URL = f"https://api.github.com/repos/{REPO}/git/trees/main?recursive=1"
RAW_BASE = f"https://raw.githubusercontent.com/{REPO}/main"


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


def main():
    print("Fetching DataDog tree...")
    tree_data = _http(TREE_URL)
    if not tree_data:
        print("ERROR: tree fetch failed"); return
    tree = json.loads(tree_data.decode("utf-8")).get("tree", [])

    # ai-skills 의 zip 만
    zips = [x for x in tree
            if x.get("path", "").startswith("samples/ai-skills/")
            and x.get("path", "").endswith(".zip")]
    print(f"ai-skills zip files: {len(zips)}")

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    fixtures = []
    ok = 0
    for i, x in enumerate(zips, 1):
        path = x["path"]
        # samples/ai-skills/malicious_intent/<name>/<version>/<file>.zip
        parts = path.split("/")
        if len(parts) < 5:
            continue
        name = parts[3]
        version = parts[4]
        fname = parts[-1]

        url = f"{RAW_BASE}/{urllib.parse.quote(path)}"
        out = OUT_DIR / fname
        if out.exists() and out.stat().st_size > 100:
            print(f"  [{i:>3}/{len(zips)}] {name[:45]:45s} already have")
            ok += 1
        else:
            data = _http(url, timeout=60)
            if data and len(data) > 100:
                out.write_bytes(data)
                ok += 1
                print(f"  [{i:>3}/{len(zips)}] {name[:45]:45s} OK ({len(data)} bytes)")
            else:
                print(f"  [{i:>3}/{len(zips)}] {name[:45]:45s} FAIL")
                continue

        fixtures.append({
            "name": name,
            "ecosystem": "ai-skills",
            "version": version,
            "label": "malicious",
            "source": "datadog/ai_skills",
            "archive_path": str(out.relative_to(ROOT / "scripts" / "eval_real_data")),
            "archive_format": "zip+password",
            "archive_inner": None,
            "_origin": path,
        })
        time.sleep(0.2)

    print(f"\n=== 결과 ===")
    print(f"  OK: {ok}/{len(zips)}")

    manifest = {
        "fixtures": fixtures,
        "generated_at": "2026-05-29",
        "note": (
            "DataDog ai-skills 카테고리 (2026-05 신규) — Claude Code / GPT 등 "
            "AI agent 의 skill (확장 도구) 영역 악성 패키지. 매니페스트 표준 "
            "제안의 진짜 target audience 영역."
        ),
        "total_in_repo": len(zips),
        "downloaded": ok,
    }
    OUT_FX.write_text(json.dumps(manifest, ensure_ascii=False, indent=2),
                      encoding="utf-8")
    print(f"\nFixture manifest: {OUT_FX}")


if __name__ == "__main__":
    main()
