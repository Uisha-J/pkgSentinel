"""정상 agentic 패키지 archive 다운로드 (Task C).

소스:
  - npm: registry.npmjs.org JSON API → tarball URL
  - PyPI: pypi.org JSON API → sdist URL

산출:
  scripts/eval_real_data/cache/agentic/npm/<name>-<version>.tgz
  scripts/eval_real_data/cache/agentic/pypi/<name>-<version>.tar.gz
  scripts/eval_real_data/agentic_fixtures.json (측정용 매니페스트)
"""
from __future__ import annotations

import json
import time
import urllib.parse
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SOURCE = ROOT / "scripts" / "eval_real_data" / "agentic_packages.json"
OUT_DIR = ROOT / "scripts" / "eval_real_data" / "cache" / "agentic"
OUT_NPM = OUT_DIR / "npm"
OUT_PYPI = OUT_DIR / "pypi"
OUT_FX = ROOT / "scripts" / "eval_real_data" / "agentic_fixtures.json"

USER_AGENT = "pkgsentinel-research/1.0 (capstone)"


def _http_get(url: str, timeout: int = 60) -> bytes | None:
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.read()
    except Exception as e:
        print(f"    fetch error: {e}")
        return None


def _http_get_json(url: str, timeout: int = 30) -> dict | None:
    b = _http_get(url, timeout)
    if not b:
        return None
    try:
        return json.loads(b.decode("utf-8"))
    except Exception:
        return None


def fetch_npm(name: str) -> tuple[str, str, bytes] | None:
    """npm registry → latest version tarball."""
    safe = urllib.parse.quote(name, safe="@/")
    meta = _http_get_json(f"https://registry.npmjs.org/{safe}")
    if not meta:
        return None
    latest = (meta.get("dist-tags") or {}).get("latest")
    if not latest:
        return None
    vmeta = (meta.get("versions") or {}).get(latest, {})
    tarball = (vmeta.get("dist") or {}).get("tarball")
    if not tarball:
        return None
    data = _http_get(tarball, timeout=120)
    if not data:
        return None
    return (latest, tarball, data)


def fetch_pypi(name: str) -> tuple[str, str, bytes] | None:
    """PyPI JSON API → sdist."""
    meta = _http_get_json(f"https://pypi.org/pypi/{urllib.parse.quote(name)}/json")
    if not meta:
        return None
    latest = meta.get("info", {}).get("version")
    if not latest:
        return None
    # sdist 우선, 없으면 wheel
    files = meta.get("urls") or []
    sdist = next((f for f in files if f.get("packagetype") == "sdist"), None)
    chosen = sdist or (files[0] if files else None)
    if not chosen:
        return None
    url = chosen.get("url")
    if not url:
        return None
    data = _http_get(url, timeout=120)
    if not data:
        return None
    return (latest, url, data)


def main():
    data = json.loads(SOURCE.read_text(encoding="utf-8"))
    npm_pkgs = data["npm_packages"]
    pypi_pkgs = data["pypi_packages"]
    OUT_NPM.mkdir(parents=True, exist_ok=True)
    OUT_PYPI.mkdir(parents=True, exist_ok=True)

    print(f"=== Task C agentic dataset 다운로드 ===")
    print(f"  npm:  {len(npm_pkgs)}")
    print(f"  PyPI: {len(pypi_pkgs)}")
    print()

    fixtures = []
    ok_npm = ok_pypi = 0
    fail_npm = fail_pypi = 0

    # npm
    print(f"--- npm ({len(npm_pkgs)}) ---")
    for i, name in enumerate(npm_pkgs, 1):
        safe_fname = name.replace("/", "__").replace("@", "_")
        r = fetch_npm(name)
        if not r:
            fail_npm += 1
            print(f"  [{i:>2}/{len(npm_pkgs)}] {name:50s}  FAIL")
            continue
        version, url, blob = r
        out = OUT_NPM / f"{safe_fname}-{version}.tgz"
        out.write_bytes(blob)
        ok_npm += 1
        fixtures.append({
            "name": name,
            "ecosystem": "npm",
            "version": version,
            "label": "benign",
            "source": "agentic_dataset",
            "archive_path": str(out.relative_to(ROOT / "scripts" / "eval_real_data")),
            "archive_format": "tgz",
            "archive_inner": None,
        })
        print(f"  [{i:>2}/{len(npm_pkgs)}] {name:50s}  OK v{version} ({len(blob)//1024} KB)")
        time.sleep(0.3)

    # PyPI
    print(f"\n--- PyPI ({len(pypi_pkgs)}) ---")
    for i, name in enumerate(pypi_pkgs, 1):
        safe_fname = name.replace("/", "__")
        r = fetch_pypi(name)
        if not r:
            fail_pypi += 1
            print(f"  [{i:>2}/{len(pypi_pkgs)}] {name:50s}  FAIL")
            continue
        version, url, blob = r
        # 확장자 추론
        ext = ".tar.gz"
        if url.endswith(".whl"): ext = ".whl"
        elif url.endswith(".zip"): ext = ".zip"
        out = OUT_PYPI / f"{safe_fname}-{version}{ext}"
        out.write_bytes(blob)
        ok_pypi += 1
        fmt = ("wheel" if ext == ".whl"
               else "zip" if ext == ".zip" else "tar.gz")
        fixtures.append({
            "name": name,
            "ecosystem": "PyPI",
            "version": version,
            "label": "benign",
            "source": "agentic_dataset",
            "archive_path": str(out.relative_to(ROOT / "scripts" / "eval_real_data")),
            "archive_format": fmt,
            "archive_inner": None,
        })
        print(f"  [{i:>2}/{len(pypi_pkgs)}] {name:50s}  OK v{version} ({len(blob)//1024} KB)")
        time.sleep(0.3)

    print(f"\n=== 결과 ===")
    print(f"  npm:  OK {ok_npm}/{len(npm_pkgs)}  FAIL {fail_npm}")
    print(f"  PyPI: OK {ok_pypi}/{len(pypi_pkgs)}  FAIL {fail_pypi}")
    print(f"  total fixtures: {len(fixtures)}")

    # fixture manifest 저장
    manifest = {
        "fixtures": fixtures,
        "generated_at": "2026-05-28",
        "note": (
            "Task C 정상 agentic 패키지 dataset — LangChain/CrewAI/MCP/LlamaIndex 등. "
            "전부 benign (registry 인기 패키지). pkgsentinel manifest ON/OFF FPR 측정용."
        ),
    }
    OUT_FX.write_text(json.dumps(manifest, ensure_ascii=False, indent=2),
                      encoding="utf-8")
    print(f"\n  saved: {OUT_FX}")


if __name__ == "__main__":
    main()
