"""benign 89개 아카이브 재다운로드 (FP 회귀 검증용). PyPI sdist + npm tarball."""
import json, urllib.request, urllib.parse
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor

ROOT = Path(__file__).resolve().parent.parent
DATA = ROOT / "scripts" / "eval_real_data"
fx = json.loads((DATA / "fixtures.json").read_text(encoding="utf-8"))["fixtures"]
ben = [x for x in fx if x.get("label") == "benign"]


def http(url, timeout=40):
    return urllib.request.urlopen(
        urllib.request.Request(url, headers={"User-Agent": "pk/1.0"}), timeout=timeout).read()


def fetch_one(x):
    name, ver, eco = x["name"], x["version"], x["ecosystem"]
    out = DATA / x["archive_path"]
    if out.exists() and out.stat().st_size > 200:
        return (name, "cached")
    out.parent.mkdir(parents=True, exist_ok=True)
    try:
        if eco == "PyPI":
            meta = json.loads(http(f"https://pypi.org/pypi/{urllib.parse.quote(name)}/json"))
            urls = meta.get("releases", {}).get(ver) or []
            sdist = next((u for u in urls if u["packagetype"] == "sdist"), None)
            if not sdist:  # fall back to latest sdist
                latest = meta["info"]["version"]
                urls = meta.get("releases", {}).get(latest, [])
                sdist = next((u for u in urls if u["packagetype"] == "sdist"), None)
            if not sdist:
                return (name, "no-sdist")
            out.write_bytes(http(sdist["url"]))
        else:  # npm
            meta = json.loads(http("https://registry.npmjs.org/" + name.replace("/", "%2F")))
            v = meta.get("versions", {}).get(ver) or meta["versions"][meta["dist-tags"]["latest"]]
            out.write_bytes(http(v["dist"]["tarball"]))
        return (name, "OK")
    except Exception as e:
        return (name, f"ERR {str(e)[:40]}")


def main():
    print(f"benign 재다운로드: {len(ben)}")
    with ThreadPoolExecutor(max_workers=10) as ex:
        res = list(ex.map(fetch_one, ben))
    from collections import Counter
    c = Counter(s.split()[0] for _, s in res)
    print("결과:", dict(c))
    for n, s in res:
        if s.startswith("ERR") or s in ("no-sdist",):
            print("  ", n, s)


if __name__ == "__main__":
    main()
