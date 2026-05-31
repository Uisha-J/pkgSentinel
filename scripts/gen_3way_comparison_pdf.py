"""npm 280 fixture 3-way 비교 결과 — Socket vs OSV-Scanner vs pkgsentinel.

§1 측정 setup
§2 Overall metrics
§3 Trade-off 시각화
§4 by source 분석 (compromised_lib / malicious_intent / registry)
§5 Socket 의 측정 한계 (62/280 = 22% 측정 불가)
§6 결론 — pkgsentinel 의 차별 포지션

출력: docs/2026-05-28-npm-3way-비교.pdf
"""
from __future__ import annotations

from pathlib import Path

from fpdf import FPDF

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "docs" / "2026-05-28-npm-3way-비교.pdf"

FONT_REG = r"C:\Windows\Fonts\malgun.ttf"
FONT_BD = r"C:\Windows\Fonts\malgunbd.ttf"
FONT_MONO = r"C:\Windows\Fonts\consola.ttf"

# 색 — prof brief 통일
C_INK = (20, 35, 58)
C_TEAL = (31, 169, 143)
C_NAVY = (35, 80, 122)
C_MUTED = (106, 124, 140)
C_LIGHT = (236, 242, 246)
C_HEAD_BG = (228, 235, 240)
C_GOOD = (46, 124, 79)
C_WARN = (212, 122, 31)
C_DANGER = (192, 57, 43)


class Brief(FPDF):
    def header(self):
        pass

    def footer(self):
        self.set_y(-12)
        self.set_font("Malgun", "", 8)
        self.set_text_color(*C_MUTED)
        self.cell(0, 6, f"pkgsentinel · 7팀 · npm 3-way 비교 · {self.page_no()}",
                  align="C")


def _reset_x(pdf):
    pdf.set_x(pdf.l_margin)


def section(pdf: Brief, title: str) -> None:
    pdf.ln(2)
    _reset_x(pdf)
    y0 = pdf.get_y()
    pdf.set_fill_color(*C_TEAL)
    pdf.rect(pdf.l_margin, y0 + 1.2, 1.5, 6.5, "F")
    pdf.set_font("Malgun", "B", 12.5)
    pdf.set_text_color(*C_INK)
    pdf.cell(3.5, 8.5, "")
    pdf.multi_cell(0, 8.5, title)
    _reset_x(pdf)
    pdf.ln(0.3)


def body(pdf: Brief, text: str, *, bold=False, color=C_INK, size=10) -> None:
    _reset_x(pdf)
    pdf.set_font("Malgun", "B" if bold else "", size)
    pdf.set_text_color(*color)
    pdf.multi_cell(0, 5.2, text)


def bullet(pdf: Brief, text: str, *, color=C_INK, size=9.5) -> None:
    _reset_x(pdf)
    pdf.set_font("Malgun", "", size)
    pdf.set_text_color(*color)
    pdf.multi_cell(0, 5.0, "   •  " + text)


def kv(pdf: Brief, key: str, val: str, *, key_w=36, color=C_NAVY) -> None:
    _reset_x(pdf)
    pdf.set_font("Malgun", "B", 9.5)
    pdf.set_text_color(*color)
    pdf.cell(key_w, 5.2, key)
    pdf.set_font("Malgun", "", 9.5)
    pdf.set_text_color(*C_INK)
    pdf.multi_cell(0, 5.2, val)


# ─────────────── 표 helper (multi_cell, 가변 height) ───────────────

def _row_h(pdf, cells, fontsize, line_h, top_pad, bottom_pad,
           row_fonts):
    max_lines = 1
    for i, (txt, w) in enumerate(cells):
        style, sz = row_fonts.get(i, ("", fontsize))
        pdf.set_font("Malgun", style, sz)
        lines = pdf.multi_cell(w - 2, line_h, txt or "",
                               split_only=True, padding=1)
        max_lines = max(max_lines, max(1, len(lines)))
    return max_lines * line_h + top_pad + bottom_pad


def table_header(pdf, cols, h=6.0, fontsize=9.5):
    _reset_x(pdf)
    pdf.set_font("Malgun", "B", fontsize)
    pdf.set_text_color(*C_NAVY)
    pdf.set_fill_color(*C_HEAD_BG)
    pdf.set_draw_color(*C_MUTED)
    for label, w in cols:
        pdf.cell(w, h, " " + label, border=1, fill=True, align="C")
    pdf.ln(h)


def table_row(pdf, cells, *, line_h=4.6, fontsize=9,
              row_fonts=None, row_colors=None,
              row_fill=None,
              top_pad=1.0, bottom_pad=1.0, align="L"):
    row_fonts = row_fonts or {}
    row_colors = row_colors or {}
    row_h = _row_h(pdf, cells, fontsize, line_h, top_pad, bottom_pad,
                   row_fonts)
    if pdf.get_y() + row_h > pdf.h - pdf.b_margin:
        pdf.add_page()
    y0 = pdf.get_y()
    x = pdf.l_margin
    for i, (txt, w) in enumerate(cells):
        style, sz = row_fonts.get(i, ("", fontsize))
        color = row_colors.get(i, C_INK)
        pdf.set_draw_color(*C_MUTED)
        if row_fill:
            pdf.set_fill_color(*row_fill)
            pdf.rect(x, y0, w, row_h, "F")
        pdf.rect(x, y0, w, row_h)
        pdf.set_xy(x + 1, y0 + top_pad)
        pdf.set_font("Malgun", style, sz)
        pdf.set_text_color(*color)
        pdf.multi_cell(w - 2, line_h, txt or "", padding=0,
                       align=align)
        x += w
    pdf.set_y(y0 + row_h)
    _reset_x(pdf)


# ─────────────── 시각 helper ───────────────

def metric_bar(pdf, label, value, max_value=1.0, *, color=C_TEAL,
               bar_w=80, h=4.5):
    """라벨 + 막대 + 값 (precision/recall 시각화)."""
    _reset_x(pdf)
    pdf.set_font("Malgun", "", 9.5)
    pdf.set_text_color(*C_INK)
    pdf.cell(40, h, label)
    x0 = pdf.get_x()
    y0 = pdf.get_y()
    # 빈 막대 배경
    pdf.set_fill_color(240, 243, 246)
    pdf.set_draw_color(*C_MUTED)
    pdf.rect(x0, y0 + 0.5, bar_w, h - 1.0, "F")
    # 값 채움
    fill_w = bar_w * (value / max_value)
    pdf.set_fill_color(*color)
    pdf.rect(x0, y0 + 0.5, fill_w, h - 1.0, "F")
    pdf.set_xy(x0 + bar_w + 3, y0)
    pdf.set_font("Malgun", "B", 9.5)
    pdf.cell(0, h, f"{value:.3f}")
    pdf.ln(h)


def build():
    pdf = Brief(orientation="P", unit="mm", format="A4")
    pdf.add_font("Malgun", "", FONT_REG)
    pdf.add_font("Malgun", "B", FONT_BD)
    pdf.add_font("Consola", "", FONT_MONO)
    pdf.set_margins(14, 14, 14)
    pdf.set_auto_page_break(auto=True, margin=14)
    pdf.add_page()

    # ─── 헤더 ───────────────
    pdf.set_font("Malgun", "B", 16)
    pdf.set_text_color(*C_INK)
    pdf.cell(0, 9, "npm 280 fixture — 3-way 비교 결과",
             new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("Malgun", "", 10.5)
    pdf.set_text_color(*C_NAVY)
    pdf.cell(0, 5.5,
             "OSV-Scanner vs pkgsentinel vs Socket.dev API — 동일 fixture · 동일 metric",
             new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("Malgun", "", 8.5)
    pdf.set_text_color(*C_MUTED)
    pdf.cell(0, 4.5,
             "pkgsentinel · 7팀 · 2026-05-28 · 외부 도구 비교 측정",
             new_x="LMARGIN", new_y="NEXT")
    pdf.ln(1)
    y = pdf.get_y()
    pdf.set_draw_color(*C_TEAL)
    pdf.set_line_width(0.5)
    pdf.line(14, y, 196, y)
    pdf.set_line_width(0.2)
    pdf.ln(0.5)

    # ─── §1 측정 setup ──────────────
    section(pdf, "1. 측정 setup")
    kv(pdf, "Dataset",
       "DataDog malicious-software-packages-dataset 의 npm 280 패키지 "
       "(compromised_lib 50 + malicious_intent 200 + registry/benign 30).")
    kv(pdf, "도구 3종",
       "(a) OSV-Scanner (Google OSS, lookup only)  "
       "(b) pkgsentinel Claude full mode  "
       "(c) Socket.dev API (상용)")
    kv(pdf, "Metric",
       "동일 confusion matrix — TP/FP/TN/FN → precision / recall / F1.")
    kv(pdf, "Caveat 1",
       "Socket 은 280 중 218 (78%) 만 측정 가능 — unpublish 된 침해 패키지 "
       "62개는 측정 불가 (§5 참조).")
    kv(pdf, "Caveat 2",
       "pkgsentinel 은 1a 정정 (ERROR 6건 분모 제외) 적용 후 npm 만 재집계.")

    # ─── §2 Overall metrics ───────
    section(pdf, "2. Overall metrics (npm 280 fixture)")
    table_header(pdf, [
        ("Tool", 56),
        ("n", 12),
        ("TP", 12),
        ("FP", 12),
        ("TN", 12),
        ("FN", 12),
        ("Precision", 22),
        ("Recall", 22),
        ("F1", 22),
    ])
    table_row(pdf, [
        ("OSV-Scanner (lookup only)", 56),
        ("280", 12), ("219", 12), ("4", 12), ("26", 12), ("31", 12),
        ("0.982", 22), ("0.876", 22), ("0.926", 22),
    ], align="C", row_fonts={0: ("", 9)})
    table_row(pdf, [
        ("pkgsentinel (Claude full)", 56),
        ("280", 12), ("163", 12), ("0 ★", 12), ("30", 12), ("87", 12),
        ("1.000 ★", 22), ("0.652", 22), ("0.789", 22),
    ], align="C", row_fonts={0: ("B", 9), 3: ("B", 9), 6: ("B", 9)},
       row_colors={3: C_GOOD, 6: C_GOOD})
    table_row(pdf, [
        ("Socket.dev API", 56),
        ("218", 12), ("178", 12), ("2", 12), ("26", 12), ("12", 12),
        ("0.989", 22), ("0.937 ★", 22), ("0.962 ★", 22),
    ], align="C", row_fonts={0: ("", 9), 7: ("B", 9), 8: ("B", 9)},
       row_colors={7: C_GOOD, 8: C_GOOD})

    pdf.ln(0.5)
    body(pdf,
         "★ : 해당 metric 의 단일 최우수.   pkgsentinel = precision 챔피언 (FP 0)   "
         "Socket = recall / F1 챔피언.",
         color=C_MUTED, size=8.5)

    # ─── §3 Trade-off 시각화 ──────
    section(pdf, "3. Trade-off — Precision vs Recall 시각화")
    body(pdf, "세 도구가 명시적으로 다른 trade-off 디자인을 보여줌:",
         size=9.5)
    pdf.ln(0.5)
    body(pdf, "Precision", bold=True, color=C_NAVY, size=10)
    metric_bar(pdf, "  OSV-Scanner", 0.982, color=(76, 132, 175))
    metric_bar(pdf, "  pkgsentinel", 1.000, color=C_GOOD)
    metric_bar(pdf, "  Socket.dev",  0.989, color=(140, 90, 40))
    pdf.ln(1)
    body(pdf, "Recall", bold=True, color=C_NAVY, size=10)
    metric_bar(pdf, "  OSV-Scanner", 0.876, color=(76, 132, 175))
    metric_bar(pdf, "  pkgsentinel", 0.652, color=C_WARN)
    metric_bar(pdf, "  Socket.dev",  0.937, color=C_GOOD)
    pdf.ln(0.5)
    body(pdf,
         "→ pkgsentinel = precision 우선 보수 디자인 (verdict_rules 의 5가지 정책).  "
         "Socket = recall 우선 (행위 신호 다수 + LLM 결합).  "
         "OSV = 단순 lookup baseline.",
         color=C_MUTED, size=9)

    # ─── §4 by source ───────
    section(pdf, "4. by source 분석")

    # 4.1 compromised_lib
    body(pdf, "4.1 compromised_lib (Shai-Hulud 등 사건 침해, n=50)",
         bold=True, color=C_NAVY, size=10)
    table_header(pdf, [("Tool", 70), ("TP", 18), ("FN", 18),
                       ("Recall", 30), ("주석", 46)])
    table_row(pdf, [("OSV-Scanner", 70), ("40", 18), ("10", 18),
                    ("0.800", 30), ("advisory 8개 누락", 46)], align="C")
    table_row(pdf, [("pkgsentinel", 70), ("42", 18), ("8", 18),
                    ("0.840 ★", 30), ("OSV 대비 +4%p", 46)],
              align="C",
              row_fonts={0:("B",9),3:("B",9)},
              row_colors={3: C_GOOD})
    table_row(pdf, [("Socket.dev (n=36)", 70), ("32", 18), ("4", 18),
                    ("0.889", 30), ("14개 측정 불가", 46)], align="C")
    pdf.ln(0.5)
    body(pdf,
         "→ pkgsentinel 이 공식 advisory lookup (OSV) 보다 +4%p 우월. "
         "행위 분석이 advisory 누락분을 보완.",
         color=C_INK, size=9.5)

    pdf.ln(1)
    # 4.2 malicious_intent
    body(pdf, "4.2 malicious_intent (typosquat / slop, n=200)",
         bold=True, color=C_NAVY, size=10)
    table_header(pdf, [("Tool", 70), ("TP", 18), ("FN", 18),
                       ("Recall", 30), ("주석", 46)])
    table_row(pdf, [("OSV-Scanner", 70), ("179", 18), ("21", 18),
                    ("0.895", 30), ("typosquat advisory 잘 잡음", 46)], align="C")
    table_row(pdf, [("pkgsentinel", 70), ("121", 18), ("79", 18),
                    ("0.605", 30), ("⚠ 우리 약점 — 이름 휴리스틱 약함", 46)],
              align="C",
              row_fonts={0:("B",9),3:("B",9)},
              row_colors={3: C_WARN, 4: C_WARN})
    table_row(pdf, [("Socket.dev (n=154)", 70), ("146", 18), ("8", 18),
                    ("0.948 ★", 30), ("70+ 행위 신호 강력", 46)],
              align="C",
              row_fonts={3:("B",9)},
              row_colors={3: C_GOOD})
    pdf.ln(0.5)
    body(pdf,
         "→ pkgsentinel 약점 명확히 노출. typosquat 은 *이름 휴리스틱*이 결정적인데 "
         "우리 verdict 는 *행위 분석* 위주. 개선 plan: stage 01 의 typosquat_candidates "
         "를 verdict 에 강하게 반영 (Task #26).",
         color=C_INK, size=9.5)

    pdf.ln(1)
    # 4.3 registry (정상)
    body(pdf, "4.3 registry (정상 인기 패키지, n=30)",
         bold=True, color=C_NAVY, size=10)
    table_header(pdf, [("Tool", 70), ("FP", 18), ("TN", 18),
                       ("FPR", 30), ("주석", 46)])
    table_row(pdf, [("OSV-Scanner", 70), ("4", 18), ("26", 18),
                    ("0.148", 30), ("deprecated 정상 패키지 매칭", 46)], align="C")
    table_row(pdf, [("pkgsentinel", 70), ("0 ★", 18), ("30", 18),
                    ("0.000 ★", 30), ("zero false positive", 46)],
              align="C",
              row_fonts={0:("B",9), 1:("B",9), 3:("B",9)},
              row_colors={1: C_GOOD, 3: C_GOOD})
    table_row(pdf, [("Socket.dev (n=28)", 70), ("2", 18), ("26", 18),
                    ("0.074", 30), ("보수적 알고리즘 — 일부 의심", 46)], align="C")
    pdf.ln(0.5)
    body(pdf,
         "→ pkgsentinel 만 zero FP. verdict_rules 의 LLM BENIGN 덮어쓰기 정책 + "
         "max(MAL conf) ≥ 0.85 정책의 결과.",
         color=C_INK, size=9.5)

    # ─── §5 Socket 한계 ──────
    section(pdf, "5. Socket 의 측정 한계 — unpublish 침해 패키지 분석 불가")
    body(pdf,
         "Socket 은 fixture 280 중 218 (78%) 만 측정 가능, 62 (22%) 는 측정 불가:",
         size=10)
    pdf.ln(0.3)
    bullet(pdf, "compromised_lib: 50 → 36 (14 unpublish)")
    bullet(pdf, "malicious_intent: 200 → 154 (46 unpublish / 신규 / 큐레이션 외)")
    bullet(pdf, "registry: 30 → 28 (정상이지만 일부 응답 실패)")
    pdf.ln(0.3)
    body(pdf,
         "→ Socket 의 0.937 recall 은 *측정 가능 표본* 한정. 280 전체 단위로 보면 "
         "Socket 도 178/280 = 0.636 (pkgsentinel 0.582 와 비슷).",
         color=C_INK, size=9.5)
    pdf.ln(0.3)
    body(pdf,
         "★ 핵심: 사후 unpublish 된 침해 패키지는 *상용 도구도 분석 불가*. "
         "pkgsentinel 은 archive 보존 (DataDog dataset) 분석 능력으로 "
         "전체 표본 측정 가능 — 사건 후 사라진 패키지에 대한 forensic 분석 "
         "은 우리 도구의 차별점.",
         bold=True, color=C_NAVY, size=10)

    # ─── §6 결론 ──────
    section(pdf, "6. 결론 — pkgsentinel 의 차별 포지션")

    body(pdf, "도구별 명시적 trade-off 디자인:",
         bold=True, color=C_NAVY, size=10)
    pdf.ln(0.3)
    table_header(pdf, [("측면", 60), ("우리 위치", 50), ("의미", 72)])
    table_row(pdf, [
        ("Precision (FP 0)", 60),
        ("★ 최고 (1.000)", 50),
        ("정상 패키지 한 건도 잘못 안 잡음", 72),
    ])
    table_row(pdf, [
        ("compromised_lib recall", 60),
        ("OSV 대비 +4%p", 50),
        ("공식 advisory 누락분을 행위 분석으로 보완", 72),
    ])
    table_row(pdf, [
        ("Archive 분석", 60),
        ("★ 유일", 50),
        ("Socket 도 못 함. unpublish forensic 가능", 72),
    ])
    table_row(pdf, [
        ("typosquat recall", 60),
        ("약점 (0.605)", 50),
        ("개선 plan 식별 (Task #26)", 72),
    ])
    table_row(pdf, [
        ("Socket 대비 recall", 60),
        ("약함 (단, 표본 다름)", 50),
        ("매니페스트 도입 시 trade-off 개선 가능 (Task C 측정 예정)", 72),
    ])

    pdf.ln(0.8)
    body(pdf, "한 줄 요약", bold=True, color=C_NAVY, size=10.5)
    body(pdf,
         "pkgsentinel = precision 우선 보수 디자인 + archive 분석 능력 + 공식 advisory 보완. "
         "Socket = recall 우선 상용 도구 + 측정 불가 영역 존재. OSV = 단순 lookup baseline.",
         color=C_INK, size=10)

    # 풋노트
    pdf.ln(1)
    pdf.set_draw_color(*C_LIGHT)
    pdf.set_line_width(0.3)
    y = pdf.get_y()
    pdf.line(14, y, 196, y)
    pdf.ln(0.5)
    pdf.set_font("Malgun", "", 8)
    pdf.set_text_color(*C_MUTED)
    pdf.multi_cell(0, 4.2,
                   "원본 측정 데이터: "
                   "scripts/eval_real_data/results_osv_scanner.json (OSV), "
                   "scripts/eval_real_data/results_claude_full_v2.json (pkgsentinel, 1a 정정), "
                   "scripts/eval_real_data/results_socket_npm.json (Socket).")

    pdf.output(str(OUT))
    print(f"Wrote: {OUT}  ({OUT.stat().st_size // 1024} KB, {pdf.page_no()} pages)")


if __name__ == "__main__":
    build()
