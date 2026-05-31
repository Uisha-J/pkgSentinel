"""DataDog PyPI malicious_intent 샘플 (시드 고정 무작위 = base 방법과 동일).

seed=42 셔플 → 앞 N개, >10MB 제외. 패키지당 1버전(사전순 첫). 재현 가능.
산출: cache/pypi_mal/*.zip + pypi_malicious_fixtures.json
"""
from __future__ import annotations
import json, random, urllib.parse, urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DATA = ROOT / "scripts" / "eval_real_data"
OUT = DATA / "cache" / "pypi_mal"
RAW = "https://raw.githubusercontent.com/DataDog/malicious-software-packages-dataset/main/samples/pypi/malicious_intent"
LIMIT = 80
SEED = 42
MAX_MB = 10


def http(url):
    return urllib.request.urlopen(urllib.request.Request(url, headers={"User-Agent": "pk/1.0"}), timeout=60).read()


def main():
    paths = json.loads((DATA / "_pypi_mal_paths.json").read_text())
    # 패키지당 1경로 (사전순 첫 = deterministic)
    by_pkg = {}
    for p in paths:
        pkg = p.split("/")[0]
        if pkg not in by_pkg or p < by_pkg[pkg]:
            by_pkg[pkg] = p
    cands = sorted(by_pkg.values())
    rng = random.Random(SEED)
    rng.shuffle(cands)

    OUT.mkdir(parents=True, exist_ok=True)
    fixtures = []
    i = 0
    for rel in cands:
        if len(fixtures) >= LIMIT:
            break
        i += 1
        url = f"{RAW}/{urllib.parse.quote(rel)}"
        try:
            data = http(url)
        except Exception as e:
            print(f"  fail {rel}: {e}"); continue
        if len(data) > MAX_MB * 1024 * 1024:
            continue
        parts = rel.split("/")
        name = parts[0]
        ver = parts[1] if len(parts) >= 3 else "?"
        fname = parts[-1]
        outp = OUT / fname
        outp.write_bytes(data)
        fixtures.append({
            "name": name, "ecosystem": "PyPI", "version": ver,
            "label": "malicious", "source": "datadog/pypi_malicious_intent",
            "archive_path": str(outp.relative_to(DATA)),
            "archive_format": "zip+password", "archive_inner": None, "_origin": rel,
        })
        if len(fixtures) % 20 == 0:
            print(f"  {len(fixtures)}/{LIMIT}")

    (DATA / "pypi_malicious_fixtures.json").write_text(
        json.dumps({"fixtures": fixtures, "n": len(fixtures),
                    "sampling": "DataDog pypi/malicious_intent, seed=42 shuffle, first N, >10MB excluded, 1 ver/pkg",
                    "population": len(by_pkg)}, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"\n다운로드 {len(fixtures)} / 모집단 {len(by_pkg)} 패키지")


if __name__ == "__main__":
    main()
