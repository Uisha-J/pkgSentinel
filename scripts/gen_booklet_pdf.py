"""발표 책자(booklet) Markdown -> PDF 변환.

gen_qna_pdf 의 렌더링 함수를 재사용하고, 책자용 표지/본문 크기만 별도 지정.

사용:
    python scripts/gen_booklet_pdf.py
"""
from __future__ import annotations

import sys
from pathlib import Path

from fpdf import FPDF
from fpdf.enums import XPos, YPos

# gen_qna_pdf 의 검증된 마크다운 렌더러 재사용
sys.path.insert(0, str(Path(__file__).resolve().parent))
import gen_qna_pdf as q  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
MD_PATH = ROOT / "docs" / "2026-05-27-booklet-v2.md"
OUT_PATH = ROOT / "docs" / "2026-05-27-booklet-v2.pdf"

FONT_REG = r"C:\Windows\Fonts\malgun.ttf"
FONT_BOLD = r"C:\Windows\Fonts\malgunbd.ttf"
FONT_MONO = r"C:\Windows\Fonts\consola.ttf"
FONT_MONO_BOLD = r"C:\Windows\Fonts\consolab.ttf"

MARGIN = 18


class BookletPDF(FPDF):
    def __init__(self):
        super().__init__(orientation="P", unit="mm", format="A4")
        self.set_margins(MARGIN, MARGIN, MARGIN)
        self.set_auto_page_break(auto=True, margin=18)
        self.add_font("Malgun", "", FONT_REG)
        self.add_font("Malgun", "B", FONT_BOLD)
        self.add_font("Mono", "", FONT_MONO)
        self.add_font("Mono", "B", FONT_MONO_BOLD)

    def footer(self):
        self.set_y(-12)
        self.set_font("Malgun", "", 8)
        self.set_text_color(120, 120, 120)
        self.cell(0, 5, f"{self.page_no()}", align="C")
        self.set_text_color(0, 0, 0)


def render_title_block(pdf: FPDF, team: str, title: str):
    """책자 상단 제목 블록 (별도 표지 없이 1페이지 상단)."""
    pdf.add_page()
    pdf.ln(2)
    pdf.set_font("Malgun", "", 12)
    pdf.set_text_color(90, 90, 90)
    pdf.cell(0, 7, team, new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.set_font("Malgun", "B", 19)
    pdf.set_text_color(20, 30, 80)
    pdf.cell(0, 10, title, new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    y = pdf.get_y() + 1
    pdf.set_draw_color(20, 30, 80)
    pdf.set_line_width(0.6)
    pdf.line(pdf.l_margin, y, pdf.w - pdf.r_margin, y)
    pdf.set_draw_color(0, 0, 0)
    pdf.set_line_width(0.2)
    pdf.ln(5)
    pdf.set_text_color(0, 0, 0)
    pdf.set_font("Malgun", "", q.BODY_SIZE)


def main() -> int:
    md_text = MD_PATH.read_text(encoding="utf-8")

    # 첫 두 줄(팀명/작품명)을 제목 블록으로 분리, 나머지를 본문 렌더
    lines = md_text.split("\n")
    team = lines[0].replace("팀명 :", "").strip() if lines else "7팀"
    title = lines[1].replace("작품명 :", "").strip() if len(lines) > 1 else ""
    body = "\n".join(lines[2:])

    pdf = BookletPDF()
    pdf.alias_nb_pages()
    render_title_block(pdf, f"팀명 : {team}", title)
    q.parse_and_render(pdf, body)

    pdf.output(str(OUT_PATH))
    print(f"Wrote: {OUT_PATH}")
    print(f"Pages: {pdf.page_no()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
