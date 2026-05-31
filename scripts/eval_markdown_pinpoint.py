"""markdown-pinpoint를 ai-skills 204개에 적용해 탐지율 측정 (n=204 동일 분모)."""
import sys, json, zipfile, tempfile, os
from pathlib import Path
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
from pkgsentinel.stages.markdown_pinpoint import scan_files, is_skill_doc

DATA = ROOT / "scripts" / "eval_real_data"
fx = json.loads((DATA / "ai_skills_fixtures.json").read_text(encoding="utf-8"))["fixtures"]

TEXT_EXT = (".md", ".markdown", ".mdx", ".txt", ".json", ".yaml", ".yml", "")


def read_files(td):
    out = {}
    for r, _, fs in os.walk(td):
        for f in fs:
            p = os.path.join(r, f)
            rel = os.path.relpath(p, td).replace("\\", "/")
            if not (is_skill_doc(rel) or f.lower().endswith((".md", ".txt", ".mdx", ".markdown"))):
                continue
            try:
                out[rel] = open(p, encoding="utf-8", errors="replace").read()
            except Exception:
                pass
    return out


def main():
    caught = 0
    total = 0
    by_cat = {}
    examples = []
    for item in fx:
        zp = DATA / item["archive_path"]
        if not zp.exists():
            continue
        total += 1
        with tempfile.TemporaryDirectory() as td:
            try:
                with zipfile.ZipFile(zp) as z:
                    z.setpassword(b"infected"); z.extractall(td)
            except Exception:
                continue
            files = read_files(td)
            rep = scan_files(files)
            if rep.is_malicious:
                caught += 1
                cats = sorted({h.category for h in rep.hits})
                key = ",".join(cats)
                by_cat[key] = by_cat.get(key, 0) + 1
                if len(examples) < 12:
                    h = rep.hits[0]
                    examples.append(f"{item['name'][:34]:34s} [{h.category}/{h.severity}] {h.desc} :: {h.evidence[:50]}")

    print(f"=== markdown-pinpoint on ai-skills ===")
    print(f"전체 {total} 중 탐지(malicious) {caught}  recall={caught/max(1,total):.3f}")
    print(f"탐지 범주 조합:")
    for k, v in sorted(by_cat.items(), key=lambda x: -x[1]):
        print(f"  {k:20s} {v}")
    print("\n예시:")
    for e in examples:
        print("  ", e)


if __name__ == "__main__":
    main()
