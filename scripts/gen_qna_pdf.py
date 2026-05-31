"""Q&A 마스터 레퍼런스 Markdown -> PDF 변환 (발표 후 질의응답용).

폰트: Malgun Gothic (Windows 기본 한글) + Consolas (코드 블록)
한글/표/코드 블록/리스트/blockquote 지원.

사용:
    python scripts/gen_qna_pdf.py
"""
from __future__ import annotations

import re
from pathlib import Path

from fpdf import FPDF
from fpdf.enums import XPos, YPos
from fpdf.fonts import FontFace

ROOT = Path(__file__).resolve().parent.parent
MD_PATH = ROOT / "docs" / "2026-05-19-qna-reference.md"
OUT_PATH = ROOT / "docs" / "2026-05-19-qna-reference.pdf"

FONT_REG = r"C:\Windows\Fonts\malgun.ttf"
FONT_BOLD = r"C:\Windows\Fonts\malgunbd.ttf"
FONT_MONO = r"C:\Windows\Fonts\consola.ttf"
FONT_MONO_BOLD = r"C:\Windows\Fonts\consolab.ttf"

# 페이지 / 사이즈 — Q&A 발표 중 빠르게 훑을 수 있도록 약간 더 큰 본문
PAGE_FMT = "A4"
MARGIN = 15
BODY_SIZE = 9.5
H1_SIZE = 17
H2_SIZE = 13
H3_SIZE = 10.8
CODE_SIZE = 8.0
TABLE_SIZE = 8.0
LINE_H = 4.8
LINE_H_TIGHT = 4.2


EMOJI_MAP = {
    "✅": "[O]", "❌": "[X]",
    "🔴": "[!!]", "🟠": "[!]", "🟡": "[~]", "🟢": "[ ]",
    "★": "*", "→": "->", "←": "<-", "↑": "^", "↓": "v",
    "≥": ">=", "≤": "<=", "≠": "!=", "—": "-", "…": "...",
    "·": "-", "≈": "~",
}


def _sanitize(text: str) -> str:
    for k, v in EMOJI_MAP.items():
        text = text.replace(k, v)
    return text


class QnAPDF(FPDF):
    def __init__(self):
        super().__init__(orientation="P", unit="mm", format=PAGE_FMT)
        self.set_margins(MARGIN, MARGIN, MARGIN)
        self.set_auto_page_break(auto=True, margin=18)
        self.add_font("Malgun", "", FONT_REG)
        self.add_font("Malgun", "B", FONT_BOLD)
        self.add_font("Mono", "", FONT_MONO)
        self.add_font("Mono", "B", FONT_MONO_BOLD)

    def header(self):
        if self.page_no() == 1:
            return
        self.set_font("Malgun", "", 8)
        self.set_text_color(120, 120, 120)
        self.cell(
            0, 5, "7팀 캡스톤 Q&A 마스터 레퍼런스",
            align="R", new_x=XPos.LMARGIN, new_y=YPos.NEXT,
        )
        self.ln(2)
        self.set_text_color(0, 0, 0)

    def footer(self):
        self.set_y(-12)
        self.set_font("Malgun", "", 8)
        self.set_text_color(120, 120, 120)
        self.cell(0, 5, f"{self.page_no()} / {{nb}}", align="C")
        self.set_text_color(0, 0, 0)


def render_inline(pdf: FPDF, text: str, font: str = "Malgun"):
    text = _sanitize(text)
    pattern = re.compile(r"(\*\*[^*]+\*\*|`[^`]+`|\[[^\]]+\]\([^)]+\))")
    parts = pattern.split(text)
    for part in parts:
        if not part:
            continue
        if part.startswith("**") and part.endswith("**"):
            pdf.set_font(font, "B", BODY_SIZE)
            pdf.write(LINE_H, part[2:-2])
            pdf.set_font(font, "", BODY_SIZE)
        elif part.startswith("`") and part.endswith("`"):
            inner = part[1:-1]
            if all(ord(c) < 128 for c in inner):
                pdf.set_font("Mono", "", CODE_SIZE)
                pdf.set_text_color(180, 30, 60)
                pdf.write(LINE_H, inner)
                pdf.set_text_color(0, 0, 0)
                pdf.set_font(font, "", BODY_SIZE)
            else:
                pdf.set_font(font, "B", BODY_SIZE)
                pdf.set_text_color(150, 30, 60)
                pdf.write(LINE_H, inner)
                pdf.set_text_color(0, 0, 0)
                pdf.set_font(font, "", BODY_SIZE)
        elif part.startswith("[") and "](" in part:
            m = re.match(r"\[([^\]]+)\]\(([^)]+)\)", part)
            if m:
                pdf.set_text_color(0, 80, 180)
                pdf.write(LINE_H, m.group(1))
                pdf.set_text_color(0, 0, 0)
        else:
            pdf.write(LINE_H, part)


def render_heading(pdf: FPDF, level: int, text: str):
    text = _sanitize(text.strip())
    if level == 1:
        pdf.ln(1)
        pdf.set_font("Malgun", "B", H1_SIZE)
        pdf.set_text_color(20, 30, 80)
        pdf.cell(0, 9, text, new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        x1 = pdf.l_margin
        x2 = pdf.w - pdf.r_margin
        y = pdf.get_y()
        pdf.set_draw_color(20, 30, 80)
        pdf.line(x1, y, x2, y)
        pdf.set_draw_color(0, 0, 0)
        pdf.ln(2.5)
    elif level == 2:
        pdf.ln(2)
        pdf.set_font("Malgun", "B", H2_SIZE)
        pdf.set_text_color(20, 30, 80)
        pdf.cell(0, 6.5, text, new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.ln(0.5)
    elif level == 3:
        pdf.ln(1)
        pdf.set_font("Malgun", "B", H3_SIZE)
        pdf.set_text_color(60, 60, 60)
        pdf.cell(0, 5.5, text, new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    else:
        pdf.ln(1)
        pdf.set_font("Malgun", "B", BODY_SIZE)
        pdf.cell(0, 5, text, new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.set_text_color(0, 0, 0)
    pdf.set_font("Malgun", "", BODY_SIZE)


def render_paragraph(pdf: FPDF, text: str):
    pdf.set_font("Malgun", "", BODY_SIZE)
    render_inline(pdf, text.strip())
    pdf.ln(5)


def render_list_item(pdf: FPDF, indent: int, marker: str, text: str):
    pdf.set_font("Malgun", "", BODY_SIZE)
    x_indent = pdf.l_margin + 4 * indent
    pdf.set_x(x_indent)
    pdf.cell(4, LINE_H, marker, new_x=XPos.RIGHT, new_y=YPos.TOP)
    render_inline(pdf, text)
    pdf.ln(LINE_H)


def render_blockquote(pdf: FPDF, text: str):
    text = _sanitize(text.strip())
    x0 = pdf.l_margin + 2
    y0 = pdf.get_y()
    pdf.set_font("Malgun", "", BODY_SIZE)
    pdf.set_text_color(60, 60, 60)
    pdf.set_x(x0 + 3)
    pdf.multi_cell(
        pdf.w - x0 - pdf.r_margin - 3, LINE_H, text,
        new_x=XPos.LMARGIN, new_y=YPos.NEXT,
    )
    y1 = pdf.get_y()
    pdf.set_draw_color(120, 130, 200)
    pdf.set_line_width(0.5)
    pdf.line(x0, y0, x0, y1)
    pdf.set_draw_color(0, 0, 0)
    pdf.set_line_width(0.2)
    pdf.set_text_color(0, 0, 0)
    pdf.ln(1)


def render_code_block(pdf: FPDF, lang: str, code: str):
    code = _sanitize(code)
    has_hangul = any(ord(c) > 127 for c in code)
    pdf.set_font("Malgun" if has_hangul else "Mono", "", CODE_SIZE)
    pdf.set_fill_color(245, 245, 248)
    pdf.set_text_color(40, 40, 40)
    y0 = pdf.get_y()
    lines = code.split("\n")
    line_h = LINE_H_TIGHT
    box_h = line_h * len(lines) + 1.5
    pdf.rect(
        pdf.l_margin, y0,
        pdf.w - pdf.l_margin - pdf.r_margin, box_h,
        style="F",
    )
    pdf.set_y(y0 + 0.5)
    for line in lines:
        pdf.set_x(pdf.l_margin + 2)
        try:
            pdf.cell(0, line_h, line, new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        except Exception:
            pdf.cell(0, line_h, line[:200], new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.set_fill_color(255, 255, 255)
    pdf.set_text_color(0, 0, 0)
    pdf.set_font("Malgun", "", BODY_SIZE)
    pdf.ln(1)


def render_table(pdf: FPDF, header: list[str], rows: list[list[str]]):
    pdf.set_font("Malgun", "", TABLE_SIZE)
    heading_face = FontFace(
        family="Malgun", emphasis="BOLD", size_pt=TABLE_SIZE,
        fill_color=(220, 225, 240), color=(0, 0, 0),
    )
    with pdf.table(
        text_align="LEFT",
        headings_style=heading_face,
        line_height=LINE_H_TIGHT,
        markdown=False,
    ) as table:
        row = table.row()
        for cell in header:
            row.cell(_strip_md(cell))
        for r in rows:
            row = table.row()
            for c in r:
                row.cell(_strip_md(c))
    pdf.ln(1)
    pdf.set_font("Malgun", "", BODY_SIZE)


def _strip_md(text: str) -> str:
    text = re.sub(r"\*\*([^*]+)\*\*", r"\1", text)
    text = re.sub(r"`([^`]+)`", r"\1", text)
    text = re.sub(r"\[([^\]]+)\]\([^)]+\)", r"\1", text)
    return _sanitize(text.strip())


def parse_and_render(pdf: FPDF, md_text: str):
    lines = md_text.split("\n")
    i = 0
    while i < len(lines):
        line = lines[i]
        stripped = line.strip()

        if not stripped:
            i += 1
            continue

        m = re.match(r"^(#{1,4})\s+(.+)$", stripped)
        if m:
            level = len(m.group(1))
            render_heading(pdf, level, m.group(2))
            i += 1
            continue

        if stripped in ("---", "***", "___"):
            pdf.ln(1)
            y = pdf.get_y()
            pdf.set_draw_color(180, 180, 180)
            pdf.line(pdf.l_margin, y, pdf.w - pdf.r_margin, y)
            pdf.set_draw_color(0, 0, 0)
            pdf.ln(3)
            i += 1
            continue

        if stripped.startswith("```"):
            lang = stripped[3:].strip()
            code_lines = []
            i += 1
            while i < len(lines) and not lines[i].strip().startswith("```"):
                code_lines.append(lines[i].rstrip())
                i += 1
            i += 1
            render_code_block(pdf, lang, "\n".join(code_lines))
            continue

        if "|" in stripped and i + 1 < len(lines):
            next_line = lines[i + 1].strip()
            if re.match(r"^\|?[\s:|-]+\|[\s:|-]+\|?$", next_line):
                header = [c.strip() for c in stripped.strip("|").split("|")]
                rows = []
                i += 2
                while i < len(lines) and "|" in lines[i].strip():
                    row = [c.strip() for c in lines[i].strip().strip("|").split("|")]
                    while len(row) < len(header):
                        row.append("")
                    rows.append(row[: len(header)])
                    i += 1
                render_table(pdf, header, rows)
                continue

        if stripped.startswith(">"):
            quote_lines = []
            while i < len(lines) and lines[i].strip().startswith(">"):
                quote_lines.append(lines[i].strip().lstrip(">").strip())
                i += 1
            render_blockquote(pdf, "\n".join(quote_lines))
            continue

        m = re.match(r"^(\s*)([-*+]|\d+\.)\s+(.+)$", line)
        if m:
            indent_spaces = len(m.group(1))
            indent = indent_spaces // 2
            marker_raw = m.group(2)
            text = m.group(3)
            marker = "•" if marker_raw in ("-", "*", "+") else marker_raw
            render_list_item(pdf, indent, marker, text)
            i += 1
            continue

        para_lines = [stripped]
        i += 1
        while i < len(lines):
            nxt = lines[i].strip()
            if not nxt:
                break
            if re.match(r"^(#{1,4}\s|```|>\s|[-*+]\s|\d+\.\s)", nxt):
                break
            if "|" in nxt and i + 1 < len(lines):
                if re.match(r"^\|?[\s:|-]+\|[\s:|-]+\|?$", lines[i + 1].strip()):
                    break
            para_lines.append(nxt)
            i += 1
        render_paragraph(pdf, " ".join(para_lines))


def render_cover(pdf: FPDF):
    pdf.add_page()
    pdf.ln(55)
    pdf.set_font("Malgun", "", 13)
    pdf.set_text_color(80, 80, 80)
    pdf.cell(0, 7, "Capstone Design 2026 PROJECT",
             new_x=XPos.LMARGIN, new_y=YPos.NEXT, align="C")
    pdf.cell(0, 7, "7팀",
             new_x=XPos.LMARGIN, new_y=YPos.NEXT, align="C")

    pdf.ln(22)
    pdf.set_font("Malgun", "B", 26)
    pdf.set_text_color(20, 30, 80)
    pdf.cell(0, 14, "Q&A 마스터 레퍼런스",
             new_x=XPos.LMARGIN, new_y=YPos.NEXT, align="C")

    pdf.ln(2)
    pdf.set_font("Malgun", "", 13)
    pdf.set_text_color(80, 80, 80)
    pdf.cell(0, 7, "LLM 추천 패키지 공급망 공격 탐지 도구",
             new_x=XPos.LMARGIN, new_y=YPos.NEXT, align="C")

    pdf.ln(4)
    line_w = 60
    cx = pdf.w / 2
    pdf.set_draw_color(20, 30, 80)
    pdf.set_line_width(0.8)
    pdf.line(cx - line_w / 2, pdf.get_y(), cx + line_w / 2, pdf.get_y())
    pdf.set_draw_color(0, 0, 0)
    pdf.set_line_width(0.2)

    pdf.ln(8)
    pdf.set_font("Malgun", "", 12)
    pdf.set_text_color(80, 80, 80)
    pdf.cell(0, 7, "발표 후 질의응답 대비 — 전 기능/파일/데이터 정리본",
             new_x=XPos.LMARGIN, new_y=YPos.NEXT, align="C")
    pdf.ln(2)
    pdf.cell(0, 7, "작성일: 2026-05-19",
             new_x=XPos.LMARGIN, new_y=YPos.NEXT, align="C")

    pdf.set_text_color(0, 0, 0)


def main() -> int:
    md_text = MD_PATH.read_text(encoding="utf-8")

    pdf = QnAPDF()
    pdf.alias_nb_pages()

    render_cover(pdf)

    pdf.add_page()
    parse_and_render(pdf, md_text)

    pdf.output(str(OUT_PATH))
    print(f"Wrote: {OUT_PATH}")
    print(f"Pages: {pdf.page_no()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
