"""markdown-pinpoint FP 측정 — benign 89개 (README 코드펜스 = FP surface)."""
import sys, json, zipfile, tarfile, tempfile, os
from pathlib import Path
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
from pkgsentinel.stages.markdown_pinpoint import scan_files, is_skill_doc

DATA = ROOT / "scripts" / "eval_real_data"
ben = json.loads((DATA / "benign_only_fixtures.json").read_text(encoding="utf-8"))["fixtures"]


def extract(zp, td):
    try:
        if str(zp).endswith((".tar.gz", ".tgz")):
            with tarfile.open(zp) as t:
                t.extractall(td)
        else:
            with zipfile.ZipFile(zp) as z:
                try:
                    z.setpassword(b"infected")
                except Exception:
                    pass
                z.extractall(td)
        return True
    except Exception:
        return False


def read_md(td):
    out = {}
    for r, _, fs in os.walk(td):
        for f in fs:
            rel = os.path.relpath(os.path.join(r, f), td).replace("\\", "/")
            if f.lower().endswith((".md", ".txt", ".markdown", ".mdx")) or is_skill_doc(rel):
                try:
                    out[rel] = open(os.path.join(r, f), encoding="utf-8", errors="replace").read()
                except Exception:
                    pass
    return out


def main():
    fp = 0
    tot = 0
    fps = []
    for item in ben:
        zp = DATA / item["archive_path"]
        if not zp.exists():
            continue
        tot += 1
        with tempfile.TemporaryDirectory() as td:
            if not extract(zp, td):
                continue
            rep = scan_files(read_md(td))
            if rep.is_malicious:
                fp += 1
                h = rep.hits[0]
                fps.append(f"{item['name']} [{h.category}/{h.severity}] {h.desc}: {h.evidence[:60]}")
    print(f"benign {tot}개 중 FP: {fp} ({100*fp/max(1,tot):.1f}%)")
    for x in fps:
        print("  FP!", x)


if __name__ == "__main__":
    main()
