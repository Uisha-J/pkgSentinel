"""옵션 A 설계 문서 — Agentic Capability Manifest vocabulary EXTEND (확장).

문제:
  - 매니페스트 declared 어휘 ↔ 도구 detected 어휘 mismatch
  - 단순 hardcoded mapping 정렬 = 측정 dataset 에 overfit (REPLACE 위험)

해법 (REPLACE 가 아닌 EXTEND):
  - 기존 자체 어휘 유지 + MITRE ATT&CK TTP 도 *추가* 지원
  - 둘 다 같은 semantic cluster 로 grouping → 자동 normalize
  - 작성자 선택권 보장 + 표준 점진 채택
  - overfit 위험 0 (외부 anchor + 호환성)

산출: docs/2026-05-28-옵션A-vocabulary-extend.pdf
"""
from __future__ import annotations

from pathlib import Path
from fpdf import FPDF

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "docs" / "2026-05-28-옵션A-vocabulary-extend.pdf"

FONT_REG = r"C:\Windows\Fonts\malgun.ttf"
FONT_BD = r"C:\Windows\Fonts\malgunbd.ttf"

C_INK = (20, 35, 58)
C_TEAL = (31, 169, 143)
C_NAVY = (35, 80, 122)
C_MUTED = (106, 124, 140)
C_LIGHT = (236, 242, 246)
C_HEAD_BG = (228, 235, 240)
C_MANIFEST = (106, 63, 191)
C_GOOD = (46, 124, 79)
C_WARN = (212, 122, 31)


class Brief(FPDF):
    def header(self):
        pass

    def footer(self):
        self.set_y(-12)
        self.set_font("Malgun", "", 8)
        self.set_text_color(*C_MUTED)
        self.cell(0, 6, f"pkgsentinel · 7팀 · 옵션 A 설계 · {self.page_no()}",
                  align="C")


def _reset_x(pdf):
    pdf.set_x(pdf.l_margin)


def section(pdf, title):
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


def body(pdf, text, *, bold=False, color=C_INK, size=10):
    _reset_x(pdf)
    pdf.set_font("Malgun", "B" if bold else "", size)
    pdf.set_text_color(*color)
    pdf.multi_cell(0, 5.2, text)


def bullet(pdf, text, *, color=C_INK, size=9.5):
    _reset_x(pdf)
    pdf.set_font("Malgun", "", size)
    pdf.set_text_color(*color)
    pdf.multi_cell(0, 5.0, "   •  " + text)


def kv(pdf, key, val, *, key_w=40, color=C_NAVY):
    _reset_x(pdf)
    pdf.set_font("Malgun", "B", 9.5)
    pdf.set_text_color(*color)
    pdf.cell(key_w, 5.2, key)
    pdf.set_font("Malgun", "", 9.5)
    pdf.set_text_color(*C_INK)
    pdf.multi_cell(0, 5.2, val)


def _row_h(pdf, cells, fontsize, line_h, top_pad, bottom_pad, row_fonts):
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


def table_row(pdf, cells, *, line_h=4.4, fontsize=8.5, row_fonts=None,
              row_colors=None, top_pad=1.0, bottom_pad=1.0, align="L"):
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
        pdf.rect(x, y0, w, row_h)
        pdf.set_xy(x + 1, y0 + top_pad)
        pdf.set_font("Malgun", style, sz)
        pdf.set_text_color(*color)
        pdf.multi_cell(w - 2, line_h, txt or "", padding=0, align=align)
        x += w
    pdf.set_y(y0 + row_h)
    _reset_x(pdf)


def build():
    pdf = Brief(orientation="P", unit="mm", format="A4")
    pdf.add_font("Malgun", "", FONT_REG)
    pdf.add_font("Malgun", "B", FONT_BD)
    pdf.set_margins(14, 14, 14)
    pdf.set_auto_page_break(auto=True, margin=14)
    pdf.add_page()

    # 헤더
    pdf.set_font("Malgun", "B", 16)
    pdf.set_text_color(*C_INK)
    pdf.cell(0, 9, "옵션 A — 매니페스트 vocabulary EXTEND (확장)",
             new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("Malgun", "", 10.5)
    pdf.set_text_color(*C_NAVY)
    pdf.cell(0, 5.5,
             "REPLACE 가 아닌 EXTEND — 기존 어휘 유지 + MITRE TTP 추가 + semantic cluster normalize",
             new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("Malgun", "", 8.5)
    pdf.set_text_color(*C_MUTED)
    pdf.cell(0, 4.5, "pkgsentinel · 7팀 · 2026-05-28 · 매니페스트 표준 v2 제안",
             new_x="LMARGIN", new_y="NEXT")
    pdf.ln(1)
    y = pdf.get_y()
    pdf.set_draw_color(*C_TEAL)
    pdf.set_line_width(0.5)
    pdf.line(14, y, 196, y)
    pdf.set_line_width(0.2)
    pdf.ln(0.5)

    # ─── §1 문제 ────────────────────
    section(pdf, "1. 문제 — Capability Ontology Mismatch")
    body(pdf,
         "Task C 측정 결과 매니페스트 ON/OFF ablation 효과 = 3%p (예상보다 작음). "
         "원인: 매니페스트 declared 어휘와 도구 detected 어휘 mismatch:",
         size=9.5)
    pdf.ln(0.3)

    table_header(pdf, [
        ("자체 매니페스트 어휘 (declared)", 90),
        ("도구의 detected vocabulary", 90),
    ])
    table_row(pdf, [
        ("net.http, net.socket", 90),
        ("network, llm-call, mcp-client", 90),
    ])
    table_row(pdf, [
        ("fs.read, fs.write", 90),
        ("filesystem-read, filesystem-write", 90),
    ])
    table_row(pdf, [
        ("shell.exec, proc.spawn", 90),
        ("shell, code-exec, dynamic-tool-load", 90),
    ])
    table_row(pdf, [
        ("env.read, secrets.read", 90),
        ("env-secrets, credential-paths", 90),
    ])
    pdf.ln(0.5)
    body(pdf,
         "→ vocabulary 차이로 모든 detected = undeclared. 단순 hardcoded mapping 정렬 "
         "(REPLACE) 은 측정 dataset 에 overfit — 사용자 우려대로 새 dataset 깨짐.",
         color=C_INK, size=9.5)

    # ─── §2 해법 원리 ────────────────
    section(pdf, "2. 해법 원리 — REPLACE 가 아닌 EXTEND")

    body(pdf, "REPLACE vs EXTEND", bold=True, color=C_NAVY, size=10)
    pdf.ln(0.2)
    table_header(pdf, [("접근", 38), ("의미", 70), ("위험", 72)])
    table_row(pdf, [
        ("REPLACE (기각)", 38),
        ("자체 어휘 → MITRE 로 교체", 70),
        ("breaking change. 기존 자료 손해. overfit 위험", 72),
    ], row_colors={0: C_WARN})
    table_row(pdf, [
        ("EXTEND (채택) ★", 38),
        ("자체 어휘 *유지* + MITRE 어휘 *추가*", 70),
        ("additive. 작성자 선택권 보장. overfit 0", 72),
    ], row_fonts={0:("B",9)}, row_colors={0: C_MANIFEST})

    pdf.ln(0.5)
    body(pdf, "EXTEND 원칙", bold=True, color=C_MANIFEST, size=10)
    bullet(pdf,
           "★ 매니페스트 작성자가 자체 어휘 / MITRE / 우리 detected 어휘 *어느 것이든* 사용 가능",
           color=C_INK)
    bullet(pdf,
           "도구 내부에서 세 어휘를 같은 semantic cluster 로 normalize",
           color=C_INK)
    bullet(pdf,
           "MITRE = 외부 anchor → 측정 dataset 무관하게 generalizable",
           color=C_INK)
    bullet(pdf,
           "표준 진화: 처음엔 자체 어휘로도 가능 → 점진적으로 MITRE 채택 유도",
           color=C_INK)
    bullet(pdf,
           "부수 효과: STIX 2.1 / SIEM 출력 자연 매핑, 학술 anchor 보강",
           color=C_INK)

    pdf.ln(0.5)
    body(pdf, "원리 다이어그램", bold=True, color=C_NAVY, size=10)
    pdf.ln(0.2)
    body(pdf,
         "[Author A] declared = {\"net.http\", \"fs.read\"}                  ← 자체 어휘 OK\n"
         "[Author B] declared = {\"T1071\", \"T1083\"}                         ← MITRE 어휘 OK\n"
         "[Author C] declared = {\"net.http\", \"T1083\"}                      ← 혼합 OK\n"
         "                          ↓\n"
         "[Normalize] semantic cluster → {network, fs-read}\n"
         "                          ↓\n"
         "[Detector] detected_clusters = {network, fs-read, exec}\n"
         "                          ↓\n"
         "[Diff] detected - declared = {exec}  ← 미선언 위험\n"
         "       → SUSPICIOUS",
         color=C_INK, size=9)

    # ─── §3 semantic cluster 표 ───────
    section(pdf, "3. Semantic Cluster — 3 vocabulary 가 같은 의미로 EXTEND")
    body(pdf,
         "같은 capability 의미를 자체/MITRE/detected 세 어휘로 표현 가능. "
         "도구는 셋 모두 같은 cluster 로 normalize:",
         size=10)
    pdf.ln(0.3)

    table_header(pdf, [
        ("Cluster", 28),
        ("자체 어휘 (사람 친화)", 44),
        ("MITRE TTP (외부 표준)", 36),
        ("우리 detected (legacy)", 64),
    ])
    table_row(pdf, [
        ("network", 28),
        ("net.http, net.socket", 44),
        ("T1071, T1071.001, T1090", 36),
        ("network, llm-call, mcp-client", 64),
    ])
    table_row(pdf, [
        ("fs-read", 28),
        ("fs.read", 44),
        ("T1083", 36),
        ("filesystem-read", 64),
    ])
    table_row(pdf, [
        ("fs-write", 28),
        ("fs.write", 44),
        ("T1565", 36),
        ("filesystem-write", 64),
    ])
    table_row(pdf, [
        ("exec", 28),
        ("shell.exec, proc.spawn, subprocess, dynamic_eval", 44),
        ("T1059, T1106", 36),
        ("shell, code-exec, dynamic-tool-load", 64),
    ])
    table_row(pdf, [
        ("secrets", 28),
        ("env.read, secrets.read", 44),
        ("T1552", 36),
        ("env-secrets, credential-paths", 64),
    ])
    table_row(pdf, [
        ("data-collect", 28),
        ("data.collect", 44),
        ("T1119", 36),
        ("memory-persistent, db-access", 64),
    ])
    table_row(pdf, [
        ("agent-comm", 28),
        ("agent.communicate", 44),
        ("T1090", 36),
        ("agent-to-agent, mcp-server", 64),
    ])

    pdf.ln(0.5)
    body(pdf,
         "→ 7개 핵심 cluster. 작성자가 어느 vocabulary 든 사용 가능 — 도구가 "
         "내부에서 cluster 단위로 비교. *세 어휘 모두 1급 시민*.",
         color=C_INK, size=9.5)
    pdf.ln(0.3)
    body(pdf, "Cluster 추가는 자유 (생태계 확장)", bold=True, color=C_NAVY, size=9.5)
    body(pdf,
         "위 7개는 핵심 baseline. 새 cluster (예: gpu, browser-control, "
         "blockchain) 추가는 표준 v2.x 확장으로. EXTEND 원칙은 새 cluster 에도 적용.",
         color=C_MUTED, size=9)

    # ─── §4 매니페스트 표준 v2 example ────
    section(pdf, "4. 매니페스트 표준 v2 — EXTEND 적용 example")

    body(pdf, "Author A — 자체 어휘만 (사람 친화)", bold=True, color=C_NAVY, size=9.5)
    body(pdf,
         "[tool.agentic]\n"
         "version = \"v2\"\n"
         "capabilities = [\"net.http\", \"fs.read\", \"shell.exec\"]\n"
         "→ 도구가 normalize: {network, fs-read, exec}",
         size=9, color=C_INK)
    pdf.ln(0.3)

    body(pdf, "Author B — MITRE 어휘만 (표준 anchor)", bold=True, color=C_NAVY, size=9.5)
    body(pdf,
         "[tool.agentic]\n"
         "version = \"v2\"\n"
         "capabilities = [\"T1071\", \"T1083\", \"T1059\"]\n"
         "→ 도구가 normalize: {network, fs-read, exec}",
         size=9, color=C_INK)
    pdf.ln(0.3)

    body(pdf, "Author C — 혼합 (점진 채택)", bold=True, color=C_NAVY, size=9.5)
    body(pdf,
         "[tool.agentic]\n"
         "version = \"v2\"\n"
         "capabilities = [\"net.http\", \"T1083\", \"shell.exec\"]\n"
         "→ 도구가 normalize: {network, fs-read, exec} (셋 다 같은 결과)",
         size=9, color=C_INK)
    pdf.ln(0.3)

    body(pdf, "★ 셋 다 동등하게 1급 시민. 도구가 cluster 기준 비교.",
         bold=True, color=C_MANIFEST, size=9.5)

    # ─── §5 overfit 회피 증명 ───
    section(pdf, "5. Overfit 회피 — EXTEND 가 어떻게 해결하나")

    table_header(pdf, [
        ("접근", 50),
        ("Overfit 위험", 30),
        ("Generalization", 30),
        ("이유", 72),
    ])
    table_row(pdf, [
        ("자체 vocabulary 만 (현 상태)", 50),
        ("중", 30),
        ("불확실", 30),
        ("ontology mismatch — 작동 X", 72),
    ])
    table_row(pdf, [
        ("REPLACE — Hardcoded mapping", 50),
        ("높음 ⚠", 30),
        ("새 dataset 깨짐", 30),
        ("측정 dataset 보면서 정렬 → bias", 72),
    ], row_colors={1: C_WARN})
    table_row(pdf, [
        ("EXTEND — 자체 + MITRE 둘 다 (★)", 50),
        ("0 ★", 30),
        ("Dataset 무관", 30),
        ("외부 anchor (MITRE) + 호환성 유지", 72),
    ], row_fonts={1:("B",8.5), 2:("B",8.5)},
       row_colors={1: C_GOOD, 2: C_GOOD})

    pdf.ln(0.5)
    body(pdf,
         "EXTEND 의 overfit 회피 메커니즘:",
         bold=True, color=C_NAVY, size=9.5)
    bullet(pdf,
           "MITRE 는 외부 사전 정의 표준 (NIST/CISA 권장) — 우리 측정 dataset 무관",
           color=C_INK)
    bullet(pdf,
           "자체 어휘 → MITRE mapping 은 *의미 기반* (cluster) 이지 *데이터 기반* 이 아님",
           color=C_INK)
    bullet(pdf,
           "새 cluster 추가 시도 같은 EXTEND 원칙 적용 — breaking change 없음",
           color=C_INK)
    bullet(pdf,
           "도구의 detected vocabulary 도 *추가* 라벨 (legacy + cluster 둘 다) — 호환",
           color=C_INK)

    # ─── §6 구현 계획 ───
    section(pdf, "6. 구현 계획 — EXTEND 단계별")

    table_header(pdf, [
        ("단계", 28),
        ("작업 (EXTEND 원칙)", 80),
        ("시간", 22),
        ("산출", 48),
    ])
    table_row(pdf, [
        ("Phase 1", 28),
        ("7개 cluster 정의 + 3-vocabulary 매핑 (이 문서)", 80),
        ("1-2일", 22),
        ("spec v2 + 예시", 48),
    ])
    table_row(pdf, [
        ("Phase 2", 28),
        ("agentic/manifest.py — declared 어휘 normalize layer 추가 "
         "(자체 + MITRE + detected 모두 인식)", 80),
        ("2일", 22),
        ("normalize() 함수 + 단위 테스트", 48),
    ])
    table_row(pdf, [
        ("Phase 3", 28),
        ("agentic/capability_detector.py — detected 가 cluster + legacy 둘 다 라벨", 80),
        ("1-2일", 22),
        ("backward compat + 새 cluster", 48),
    ])
    table_row(pdf, [
        ("Phase 4", 28),
        ("Reference manifest 공개 — LangChain/MCP 등 (셋 다 vocabulary OK)", 80),
        ("1주", 22),
        ("GitHub 공개 + PR proposal", 48),
    ])
    table_row(pdf, [
        ("Phase 5", 28),
        ("Task C 재측정 — cluster 기준 declared ⊇ detected 비교", 80),
        ("4-6h", 22),
        ("진짜 매니페스트 효과 정량", 48),
    ])

    pdf.ln(0.3)
    body(pdf,
         "→ 총 약 2주. Phase 1 (이 문서) 가 회신 메일 immediate evidence. "
         "Phase 2-3 가 호환성 핵심.",
         color=C_MUTED, size=9.5)

    # ─── §7 예상 효과 ───
    section(pdf, "7. 예상 효과 — counter-factual 기준")
    body(pdf,
         "옵션 E counter-factual simulation (별첨 PDF) 결과 + 옵션 A 정렬 시 잠재 효과:",
         size=10)
    pdf.ln(0.3)

    table_header(pdf, [
        ("측정", 64),
        ("Current", 24),
        ("MITRE 정렬 후 (예상)", 40),
        ("개선", 50),
    ])
    table_row(pdf, [
        ("정상 agentic 100 — FPR", 64),
        ("28.0%", 24),
        ("약 7-10%", 40),
        ("-18%p ~ -21%p", 50),
    ])
    table_row(pdf, [
        ("악성 agentic 34 — Recall", 64),
        ("20.6%", 24),
        ("약 30-40%", 40),
        ("+10%p ~ +20%p (declared diff)", 50),
    ])
    table_row(pdf, [
        ("agentic F1", 64),
        ("약 0.30", 24),
        ("약 0.50-0.55", 40),
        ("+0.20 이상", 50),
    ])

    pdf.ln(0.3)
    body(pdf,
         "★ 예상치는 옵션 E counter-factual (FPR -7%p) + declared diff 정밀화 추정. "
         "실측은 Phase 5 에서.",
         color=C_MUTED, size=9)

    # ─── §8 결론 ───
    section(pdf, "8. 결론 — EXTEND 가 강화하는 contribution")

    body(pdf, "원래 contribution (v1)", bold=True, color=C_NAVY, size=10)
    bullet(pdf, "Agentic capability 선언 표준 — declared ↔ detected diff 검증")

    pdf.ln(0.3)
    body(pdf, "옵션 A — EXTEND 가 추가하는 contribution (v2)",
         bold=True, color=C_MANIFEST, size=10)
    bullet(pdf,
           "★ Semantic cluster 7개 + 3 vocabulary 동시 지원 (자체 + MITRE + detected)",
           color=C_INK)
    bullet(pdf,
           "MITRE ATT&CK 채택 — 외부 표준 anchor (NIST/CISA 권장)",
           color=C_INK)
    bullet(pdf,
           "★ EXTEND 원칙 — 작성자 선택권 보장 + 점진적 채택",
           color=C_INK)
    bullet(pdf,
           "측정 dataset 무관 — overfit 위험 0 (REPLACE 의 함정 회피)",
           color=C_INK)
    bullet(pdf,
           "Backward compat — 기존 자체 어휘 매니페스트 그대로 작동",
           color=C_INK)
    bullet(pdf,
           "Forward compat — 새 cluster 추가도 EXTEND 원칙",
           color=C_INK)
    bullet(pdf,
           "부수 효과: STIX/TAXII/SIEM 자연 매핑, 학술 anchor 견고",
           color=C_INK)

    pdf.ln(0.3)
    body(pdf, "한 줄 요약", bold=True, color=C_NAVY, size=10.5)
    body(pdf,
         "표준화 = REPLACE 가 아닌 EXTEND. 자체 + MITRE + detected 세 vocabulary 를 "
         "같은 cluster 로 normalize. 작성자 선택권 보장하며 overfit 회피 + 학술 anchor 강화. "
         "매니페스트 표준 제안의 견고성과 채택성을 동시에 확보.",
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
                   "관련 자료: 2026-05-28-TaskC-agentic-FPR.pdf (현재 ablation 결과), "
                   "results_option_e_simulation.json (counter-factual). "
                   "MITRE ATT&CK: attack.mitre.org/techniques/enterprise/.")

    pdf.output(str(OUT))
    print(f"Wrote: {OUT}  ({OUT.stat().st_size // 1024} KB, {pdf.page_no()} pages)")


if __name__ == "__main__":
    build()
