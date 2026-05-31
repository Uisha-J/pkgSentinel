"""대본(출처포함) + 시스템 설명서 → 하나의 PDF (Edge headless print-to-pdf).

한글 폰트는 Edge 렌더링이 그대로 처리.
"""
import subprocess
import sys
from pathlib import Path

import markdown

DOCS = Path(__file__).resolve().parent.parent / "docs"
SCRIPT_MD = DOCS / "2026-05-31-발표대본-출처포함.md"
MANUAL_MD = DOCS / "2026-05-31-시스템-설명서.md"
OUT_HTML = DOCS / "2026-05-31-발표대본+설명서.html"
OUT_PDF = DOCS / "2026-05-31-발표대본+설명서.pdf"

EDGE = r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"

CSS = """
@page { size: A4; margin: 16mm 14mm; }
* { box-sizing: border-box; }
body {
  font-family: "Malgun Gothic","맑은 고딕",system-ui,sans-serif;
  font-size: 10.5pt; line-height: 1.5; color: #1a1a1a; margin: 0;
}
h1 { font-size: 18pt; border-bottom: 3px solid #2563eb; padding-bottom: 6px;
     margin: 0 0 14px; color: #1e3a8a; }
h2 { font-size: 13.5pt; margin: 20px 0 8px; color: #1e40af;
     border-left: 5px solid #2563eb; padding-left: 8px; }
h3 { font-size: 11.5pt; margin: 14px 0 6px; color: #1e293b; }
p, li { margin: 4px 0; }
blockquote { background:#f1f5f9; border-left:4px solid #94a3b8; margin:8px 0;
             padding:6px 12px; color:#475569; font-size:9.8pt; }
code { background:#f1f5f9; padding:1px 4px; border-radius:3px;
       font-family:"Consolas",monospace; font-size:9.5pt; color:#be123c; }
em { color:#0369a1; font-style:normal; font-size:9.3pt; }
table { border-collapse: collapse; width:100%; margin:8px 0; font-size:9.3pt; }
th,td { border:1px solid #cbd5e1; padding:4px 7px; text-align:left;
        vertical-align:top; }
th { background:#e0e7ff; font-weight:700; color:#1e293b; }
tr:nth-child(even) td { background:#f8fafc; }
hr { border:none; border-top:1px solid #e2e8f0; margin:14px 0; }
strong { color:#0f172a; }
.docbreak { page-break-before: always; }
.cover { text-align:center; padding-top:60px; }
.cover h1 { border:none; font-size:26pt; color:#1e3a8a; }
.cover .sub { font-size:13pt; color:#475569; margin-top:10px; }
.cover .meta { font-size:10pt; color:#94a3b8; margin-top:40px; }
"""

def md2html(text: str) -> str:
    return markdown.markdown(
        text, extensions=["tables", "fenced_code", "sane_lists", "nl2br"]
    )

def main() -> int:
    script_html = md2html(SCRIPT_MD.read_text(encoding="utf-8"))
    manual_html = md2html(MANUAL_MD.read_text(encoding="utf-8"))

    html = f"""<!doctype html><html lang="ko"><head><meta charset="utf-8">
<title>pkgsentinel 발표 대본 + 시스템 설명서</title>
<style>{CSS}</style></head><body>
<div class="cover">
  <h1>pkgsentinel</h1>
  <div class="sub">발표 대본 + 시스템 설명서 (QnA 참조용)</div>
  <div class="meta">7팀 캡스톤 · 2026-05-31<br>
  Part 1. 발표 대본(출처 표기) &nbsp;|&nbsp; Part 2. 시스템 설명서</div>
</div>
<div class="docbreak">{script_html}</div>
<div class="docbreak">{manual_html}</div>
</body></html>"""

    OUT_HTML.write_text(html, encoding="utf-8")
    print(f"HTML written: {OUT_HTML}")

    if OUT_PDF.exists():
        OUT_PDF.unlink()
    cmd = [
        EDGE, "--headless", "--disable-gpu", "--no-pdf-header-footer",
        f"--print-to-pdf={OUT_PDF}",
        f"file:///{OUT_HTML.as_posix()}",
    ]
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
    if OUT_PDF.exists() and OUT_PDF.stat().st_size > 0:
        print(f"PDF written: {OUT_PDF}  ({OUT_PDF.stat().st_size//1024} KB)")
        return 0
    print("PDF FAILED", r.returncode, r.stderr[:500])
    return 1

if __name__ == "__main__":
    sys.exit(main())
