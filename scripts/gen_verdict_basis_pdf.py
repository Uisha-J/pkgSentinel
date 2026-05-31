"""교수님 피드백 #5 응답 — 판정 근거 1페이지 PDF.

내용:
  §1 판정 결정 트리 (Verdict 6종 + 조건)
  §2 MALICIOUS 판정 3-AND 조건
  §3 5가지 설계 원칙 (verdict_rules.py 주석 인용)
  §4 임계값 표 + ablation 측정 예정 표기
  §5 confidence 출처
  §6 한계 명시

출력: docs/2026-05-28-판정근거-1pager.pdf
"""
from __future__ import annotations

from pathlib import Path

from fpdf import FPDF

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "docs" / "2026-05-28-판정근거-1pager.pdf"

FONT_REG = r"C:\Windows\Fonts\malgun.ttf"
FONT_BD = r"C:\Windows\Fonts\malgunbd.ttf"
FONT_MONO = r"C:\Windows\Fonts\consola.ttf"

# 색 (prof brief 와 통일)
C_INK = (20, 35, 58)
C_TEAL = (31, 169, 143)
C_NAVY = (35, 80, 122)
C_MUTED = (106, 124, 140)
C_LIGHT = (236, 242, 246)
C_DANGER = (192, 57, 43)
C_WARN = (212, 122, 31)


class Brief(FPDF):
    def header(self):
        pass

    def footer(self):
        self.set_y(-12)
        self.set_font("Malgun", "", 8)
        self.set_text_color(*C_MUTED)
        self.cell(0, 6,
                  f"pkgsentinel · 7팀 · 판정 근거 (1-pager) · {self.page_no()}",
                  align="C")


def _reset_x(pdf):
    pdf.set_x(pdf.l_margin)


def section(pdf: Brief, title: str) -> None:
    pdf.ln(2)
    _reset_x(pdf)
    y0 = pdf.get_y()
    pdf.set_fill_color(*C_TEAL)
    pdf.rect(pdf.l_margin, y0 + 1.0, 1.4, 5.5, "F")
    pdf.set_font("Malgun", "B", 11.5)
    pdf.set_text_color(*C_INK)
    pdf.cell(3, 7, "")
    pdf.multi_cell(0, 7, title)
    _reset_x(pdf)
    pdf.ln(0.3)


def body(pdf: Brief, text: str, *, bold=False, color=C_INK, size=9.5) -> None:
    _reset_x(pdf)
    pdf.set_font("Malgun", "B" if bold else "", size)
    pdf.set_text_color(*color)
    pdf.multi_cell(0, 4.8, text)


def code(pdf: Brief, text: str, *, color=C_INK) -> None:
    _reset_x(pdf)
    pdf.set_font("Consola", "", 8.5)
    pdf.set_text_color(*color)
    pdf.set_fill_color(245, 248, 250)
    pdf.multi_cell(0, 4.4, text, fill=True)


def kv(pdf: Brief, key: str, val: str, *, key_w=44) -> None:
    _reset_x(pdf)
    pdf.set_font("Malgun", "B", 9.5)
    pdf.set_text_color(*C_NAVY)
    pdf.cell(key_w, 5.2, key)
    pdf.set_font("Malgun", "", 9.5)
    pdf.set_text_color(*C_INK)
    pdf.multi_cell(0, 5.2, val)


def table_row(pdf: Brief, cols: list[tuple[str, float]],
              *, bold=False, header=False) -> None:
    _reset_x(pdf)
    pdf.set_font("Malgun", "B" if (bold or header) else "", 9)
    if header:
        pdf.set_text_color(*C_NAVY)
        pdf.set_fill_color(*C_LIGHT)
    else:
        pdf.set_text_color(*C_INK)
    h = 5.2
    for text, w in cols:
        if header:
            pdf.cell(w, h, " " + text, border=0, fill=True)
        else:
            pdf.cell(w, h, " " + text, border="B")
    pdf.ln(h)


def build() -> None:
    pdf = Brief(orientation="P", unit="mm", format="A4")
    pdf.add_font("Malgun", "", FONT_REG)
    pdf.add_font("Malgun", "B", FONT_BD)
    pdf.add_font("Consola", "", FONT_MONO)
    pdf.set_margins(16, 14, 16)
    pdf.set_auto_page_break(auto=True, margin=12)
    pdf.add_page()

    # ── 헤더 ────────────────────────────────────
    pdf.set_font("Malgun", "B", 17)
    pdf.set_text_color(*C_INK)
    pdf.cell(0, 9, "판정 근거 (Verdict Logic) — 1-pager",
             new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("Malgun", "", 10)
    pdf.set_text_color(*C_NAVY)
    pdf.cell(0, 5.5,
             "교수님 피드백 #5 — malicious HIGH confidence 판정 기준 및 설계 근거",
             new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("Malgun", "", 8.5)
    pdf.set_text_color(*C_MUTED)
    pdf.cell(0, 4.5,
             "pkgsentinel · 7팀 · 2026-05-28 · 코드 기준 (src/pkgsentinel/verdict_rules.py)",
             new_x="LMARGIN", new_y="NEXT")
    pdf.ln(1)
    y = pdf.get_y()
    pdf.set_draw_color(*C_TEAL)
    pdf.set_line_width(0.5)
    pdf.line(16, y, 194, y)
    pdf.set_line_width(0.2)
    pdf.ln(0.5)

    # ── §1 판정 결정 트리 ─────────────────────
    section(pdf, "1. 판정 결정 — Verdict 6종 + 조건 (코드 line 164~222)")
    table_row(pdf, [("Verdict", 28), ("판정 조건", 150)], header=True)
    table_row(pdf, [
        ("MALICIOUS", 28),
        ("high TTP severity ≥ 1  AND  LLM ∋ MALICIOUS  AND  "
         "max(MAL conf) ≥ 0.85", 150),
    ])
    table_row(pdf, [
        ("HIGH_RISK", 28),
        ("(strong TTP sim ≥ 0.85  ∨  version_diff critical)  "
         "AND  LLM ∈ {SUS, MAL}", 150),
    ])
    table_row(pdf, [
        ("SUSPICIOUS", 28),
        ("weak TTP (0.70~0.85)  ∨  version_diff any  ∨  "
         "LLM SUS evidence ≥ 2 (quorum)", 150),
    ])
    table_row(pdf, [
        ("CLEAN", 28),
        ("위 어디에도 안 걸림. weak TTP + LLM=BENIGN 도 BENIGN 덮어씀.", 150),
    ])
    table_row(pdf, [
        ("ERROR", 28),
        ("필수 stage (08 Behavior · 11 TTP · 16 LLM) 중 1 개 이상 실패 — "
         "부분 판정 금지.", 150),
    ])
    table_row(pdf, [
        ("CANNOT_ANALYZE", 28),
        ("Stage 00 에서 레지스트리 미등록 확정.", 150),
    ])

    # ── §2 MALICIOUS 3-AND ────────────────────
    section(pdf, "2. MALICIOUS 판정 — 3 조건 AND")
    body(pdf,
         "셋 다 만족해야만 MALICIOUS. 하나라도 모자라면 자동으로 HIGH_RISK 이하로 강등.",
         size=9.5)
    pdf.ln(0.5)
    kv(pdf, "① high TTP", "L3 (Stage 11) 의 TTP 임베딩 매칭 중 severity = HIGH 가 1 개 이상.")
    kv(pdf, "② LLM MAL", "L4 (Stage 16) Claude 3-agent 중 1 개라도 MALICIOUS 답.")
    kv(pdf, "③ max conf ≥ 0.85",
       "위 LLM MALICIOUS evidence 중 가장 신뢰도 높은 것의 self-reported confidence.")
    pdf.ln(0.5)
    body(pdf,
         "→ 'max 기반' 이 중요. 평균이 아닌 max 인 이유는 §3 의 H-6 fix 참고.",
         color=C_MUTED, size=8.5)

    # ── §3 5가지 설계 원칙 ────────────────────
    section(pdf, "3. 5가지 설계 원칙 (verdict_rules.py 주석 인용)")

    kv(pdf, "Trust by Verification",
       "패키지 나이 · 인기도 · 다운로드 수 일절 미참조 (line 6). "
       "Shai-Hulud 같은 유명 패키지 감염을 봐주지 않기 위함.")
    kv(pdf, "부분 판정 금지",
       "필수 stage 3 개 (08·11·16) 중 1 개라도 실패하면 ERROR (line 7). "
       "분석 불완전 시 false negative 방지.")
    kv(pdf, "BENIGN 덮어쓰기",
       "LLM 이 정상으로 본 weak TTP 매칭은 SUSPICIOUS 로 승격 안 됨 "
       "(line 10~11). False positive 억제.")
    kv(pdf, "max(conf) ≥ 0.85",
       "H-6 fix. 평균을 쓰면 진짜 exfil 체인 옆에 저신뢰 잡음 1 개만 섞여도 "
       "평균이 깎여 MALICIOUS → HIGH_RISK 로 강등됐던 실제 버그. "
       "단일 강한 증거 기준으로 변경 (line 150~159).")
    kv(pdf, "LLM-only quorum = 2",
       "단일 LLM 의심 evidence 로 SUSPICIOUS 승격 안 함 (line 56~59). "
       "대량 분석에서 FP 누적 억제.")

    # ── §4 임계값 표 ──────────────────────────
    section(pdf, "4. 임계값 — 현재 값 + 근거 + 보강 계획")
    table_row(pdf, [
        ("임계값", 24), ("위치", 64), ("현재 근거", 60), ("보강", 30),
    ], header=True)
    table_row(pdf, [
        ("0.85", 24),
        ("strong TTP / MAL conf", 64),
        ("Stage 4 임베딩 cosine 분포 분석", 60),
        ("ablation 측정 예정", 30),
    ])
    table_row(pdf, [
        ("0.70", 24),
        ("weak TTP 매칭 하한", 64),
        ("그 이하는 noise 컷", 60),
        ("ablation 측정 예정", 30),
    ])
    table_row(pdf, [
        ("0.50", 24),
        ("LLM quorum 입력 필터", 64),
        ("그 미만은 LLM 자신도 확신 없음", 60),
        ("경험값 유지", 30),
    ])
    pdf.ln(0.5)
    body(pdf,
         "[v2 보강 예정] DataDog 543 fixture 에 대해 threshold 0.80/0.85/0.90 "
         "각각으로 돌려 recall / FPR / F1 측정 → optimal threshold 검증.",
         color=C_WARN, size=8.5)

    # ── §5 confidence 출처 ────────────────────
    section(pdf, "5. confidence 가 어디서 오는가")
    kv(pdf, "TTP similarity",
       "Stage 11 — sentence-transformer (MiniLM-L6) 임베딩 cosine similarity. "
       "0.0 ~ 1.0 연속값.")
    kv(pdf, "LLM confidence",
       "Stage 16 — Claude 3-agent 응답의 self-reported confidence (0.0 ~ 1.0). "
       "각 에이전트 (semantic/diff/dependency) 가 자신의 판정에 대한 확신도를 보고.")
    kv(pdf, "Rule confidence",
       "Stage 11 의 규칙 기반 매칭 (apply_rules) 적중은 결정적이므로 1.0 으로 고정.")
    kv(pdf, "Evidence aggregation",
       "단일 Evidence 객체에 (TTP severity + similarity + LLM verdict + "
       "confidence) 가 모두 묶여 들어감. 판정 함수는 이 evidence 리스트와 "
       "stage_results 만 입력으로 받음 (메타데이터 의존 X).")

    # ── §6 한계 ───────────────────────────────
    section(pdf, "6. 한계 — 정직히")
    body(pdf,
         "• 47-indicator 개별 가중치는 휴리스틱 — 학술 ablation 측정 없음.\n"
         "• Agentic 자동 판별 threshold 5 점도 경험값 — FP/FN 측정 미진행.\n"
         "• 임계값 0.85 / 0.70 / 0.5 의 ablation 측정 미수행 (v2 에서 보강).\n"
         "• LLM self-reported confidence 의 calibration 평가 없음 (Claude 가 보고하는 "
         "0.9 가 실제로 90% 정확한지 확인 안 됨).",
         size=9.0)

    # ── 풋터 ──────────────────────────────────
    pdf.ln(1)
    pdf.set_draw_color(*C_LIGHT)
    pdf.set_line_width(0.3)
    y = pdf.get_y()
    pdf.line(16, y, 194, y)
    pdf.ln(0.5)
    pdf.set_font("Malgun", "", 8)
    pdf.set_text_color(*C_MUTED)
    pdf.multi_cell(0, 4.0,
                   "참고 코드: src/pkgsentinel/verdict_rules.py (메인 결정), "
                   "src/pkgsentinel/stages/stage4_ttp_match.py (TTP 임베딩 + 임계값), "
                   "src/pkgsentinel/stages/stage5_multi_agent.py (LLM 3-agent), "
                   "src/pkgsentinel/agentic/classifier.py (매니페스트 diff).")

    pdf.output(str(OUT))
    print(f"Wrote: {OUT}  ({OUT.stat().st_size // 1024} KB, {pdf.page_no()} pages)")


if __name__ == "__main__":
    build()
