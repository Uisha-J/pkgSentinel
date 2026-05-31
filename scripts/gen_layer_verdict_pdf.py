"""교수님 송부용 — L0~L6 동작구조 + MALICIOUS 판정 PDF (제목 없음).

§1. L0~L6 동작 구조 (입력 → 처리 → 출력) + Agentic Manifest 작용 컬럼
§2. MALICIOUS 판정 기준 (verdict_rules.py 현재 코드 기준)

출력: docs/2026-05-28-layer-verdict.pdf
"""
from __future__ import annotations

from pathlib import Path

from fpdf import FPDF

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "docs" / "2026-05-28-layer-verdict.pdf"

FONT_REG = r"C:\Windows\Fonts\malgun.ttf"
FONT_BD = r"C:\Windows\Fonts\malgunbd.ttf"
FONT_MONO = r"C:\Windows\Fonts\consola.ttf"

C_INK = (20, 35, 58)
C_TEAL = (31, 169, 143)
C_NAVY = (35, 80, 122)
C_MUTED = (106, 124, 140)
C_LIGHT = (236, 242, 246)
C_HEAD_BG = (228, 235, 240)
C_MANIFEST = (106, 63, 191)  # 보라 — 매니페스트 강조


class Brief(FPDF):
    def header(self):
        pass

    def footer(self):
        self.set_y(-12)
        self.set_font("Malgun", "", 8)
        self.set_text_color(*C_MUTED)
        self.cell(0, 6,
                  f"pkgsentinel · 7팀 · {self.page_no()}",
                  align="C")


def _reset_x(pdf):
    pdf.set_x(pdf.l_margin)


def section(pdf: Brief, title: str) -> None:
    pdf.ln(2)
    _reset_x(pdf)
    y0 = pdf.get_y()
    pdf.set_fill_color(*C_TEAL)
    pdf.rect(pdf.l_margin, y0 + 1.2, 1.5, 6.5, "F")
    pdf.set_font("Malgun", "B", 13)
    pdf.set_text_color(*C_INK)
    pdf.cell(3.5, 9, "")
    pdf.multi_cell(0, 9, title)
    _reset_x(pdf)
    pdf.ln(0.3)


def body(pdf: Brief, text: str, *, bold=False, color=C_INK, size=10) -> None:
    _reset_x(pdf)
    pdf.set_font("Malgun", "B" if bold else "", size)
    pdf.set_text_color(*color)
    pdf.multi_cell(0, 5.2, text)


def kv(pdf: Brief, key: str, val: str, *, key_w=40, color=C_NAVY) -> None:
    _reset_x(pdf)
    pdf.set_font("Malgun", "B", 10)
    pdf.set_text_color(*color)
    pdf.cell(key_w, 5.5, key)
    pdf.set_font("Malgun", "", 10)
    pdf.set_text_color(*C_INK)
    pdf.multi_cell(0, 5.5, val)


# ─────────────── 표 헬퍼 (multi_cell row, 가변 높이) ───────────────

def _wrap_lines(pdf: Brief, text: str, width: float, font_size: float) -> int:
    """multi_cell 가 그릴 라인 수를 미리 계산."""
    pdf.set_font("Malgun", "", font_size)
    if not text:
        return 1
    # split_only=True 로 라인만 받음
    lines = pdf.multi_cell(width, 4.6, text, split_only=True, padding=1)
    return max(1, len(lines))


def table_header(pdf: Brief, cols: list[tuple[str, float]],
                 *, h: float = 6.5, fontsize: float = 9.5) -> None:
    _reset_x(pdf)
    pdf.set_font("Malgun", "B", fontsize)
    pdf.set_text_color(*C_NAVY)
    pdf.set_fill_color(*C_HEAD_BG)
    pdf.set_draw_color(*C_MUTED)
    for label, w in cols:
        pdf.cell(w, h, " " + label, border=1, fill=True)
    pdf.ln(h)


def table_row(pdf: Brief, cells: list[tuple[str, float]],
              *, line_h: float = 4.6, fontsize: float = 9,
              row_fonts: dict[int, tuple[str, float]] | None = None,
              row_colors: dict[int, tuple[int, int, int]] | None = None,
              top_pad: float = 1.0, bottom_pad: float = 1.0) -> None:
    """각 셀이 multi_cell 로 그려지는 표 행. 높이 자동."""
    row_fonts = row_fonts or {}
    row_colors = row_colors or {}

    # 1) 가장 큰 라인 수 계산
    max_lines = 1
    line_counts = []
    for i, (txt, w) in enumerate(cells):
        style, sz = row_fonts.get(i, ("", fontsize))
        pdf.set_font("Malgun", style, sz)
        lines = pdf.multi_cell(w - 2, line_h, txt or "",
                               split_only=True, padding=1)
        n = max(1, len(lines))
        line_counts.append(n)
        if n > max_lines:
            max_lines = n
    row_h = max_lines * line_h + top_pad + bottom_pad

    # page break
    if pdf.get_y() + row_h > pdf.h - pdf.b_margin:
        pdf.add_page()

    y0 = pdf.get_y()
    x = pdf.l_margin

    # 2) 각 셀 그리기 — multi_cell + 별도 border rectangle
    for i, (txt, w) in enumerate(cells):
        style, sz = row_fonts.get(i, ("", fontsize))
        color = row_colors.get(i, C_INK)

        # 셀 border
        pdf.set_draw_color(*C_MUTED)
        pdf.rect(x, y0, w, row_h)

        # 텍스트 (top_pad 만큼 아래에서 시작)
        pdf.set_xy(x + 1, y0 + top_pad)
        pdf.set_font("Malgun", style, sz)
        pdf.set_text_color(*color)
        pdf.multi_cell(w - 2, line_h, txt or "", padding=0)

        x += w

    pdf.set_y(y0 + row_h)
    _reset_x(pdf)


def build() -> None:
    pdf = Brief(orientation="P", unit="mm", format="A4")
    pdf.add_font("Malgun", "", FONT_REG)
    pdf.add_font("Malgun", "B", FONT_BD)
    pdf.add_font("Consola", "", FONT_MONO)
    pdf.set_margins(14, 14, 14)
    pdf.set_auto_page_break(auto=True, margin=14)
    pdf.add_page()

    # ─── §1. L0~L6 동작 구조 ─────────────────────
    section(pdf, "1. L0–L6 동작 구조 — 입력 → 처리 → 출력 + Agentic Manifest 작용")
    body(pdf,
         "각 layer 는 이전 layer 출력 (또는 외부 입력) 을 받아 처리하고 "
         "다음 layer 의 입력 또는 최종 verdict 의 입력이 된다. "
         "Agentic Capability Manifest 는 별도 직교 검증 layer 로, "
         "L1 의 에이전트 판별 결과를 trigger 로 L2/L3 의 detected capability 와 "
         "작성자 declared 의 차이를 계산한다 (보라색 컬럼).",
         color=C_MUTED, size=9)
    pdf.ln(0.5)

    # 표 컬럼 폭 (총 A4 - margin = 182mm)
    cols_h = [
        ("L",       8.0),
        ("이름",     30.0),
        ("입력 → 처리 → 출력",  94.0),
        ("Manifest 작용", 50.0),
    ]
    table_header(pdf, cols_h, h=6.5, fontsize=9.5)

    # L0
    table_row(pdf, [
        ("L0", 8.0),
        ("known-malicious DB 대조", 30.0),
        ("입력: (ecosystem, package_name)\n"
         "처리: SQLCipher DB known_malicious 테이블 lookup "
         "(OSV·OSSF malicious-packages 캐시). typosquat 후보 (편집거리 ≤ 2) 동시 검색.\n"
         "출력: exact_match flag + advisory_id / typosquat_candidates", 94.0),
        ("—  (DB lookup 만, 매니페스트와 무관)", 50.0),
    ], row_colors={3: C_MUTED})

    # L1
    table_row(pdf, [
        ("L1", 8.0),
        ("소스 추출 + 에이전트 판별", 30.0),
        ("입력: 패키지 archive (zip/tar.gz/wheel)\n"
         "처리: 메모리 스트리밍 unpack → setup.py·__init__.py·package.json 등 핵심 파일 추출. "
         "12개 가중 신호 (패키지명 / description / ReAct / MCP server / agent loop / "
         "LLM SDK dep / 데코레이터 / function-calling schema / vector store) 합산.\n"
         "출력: source files dict + is_agentic flag (점수 ≥ 5)", 94.0),
        ("★ trigger\n"
         "is_agentic = True 면 L1.5 매니페스트 검증 layer 활성화. "
         "pyproject.toml [tool.agentic] (또는 package.json agentic) 파싱.", 50.0),
    ], row_colors={3: C_MANIFEST}, row_fonts={3: ("B", 9)})

    # L2
    table_row(pdf, [
        ("L2", 8.0),
        ("코드 행위 시퀀스 추출", 30.0),
        ("입력: source files dict (L1 출력)\n"
         "처리: AST (Python) / tree-sitter (JS·TS) 로 함수 호출 그래프 추출. "
         "각 호출을 AttackDimension 4종 (INFO_READING / ENCODING / "
         "PAYLOAD_EXECUTION / DATA_TRANSMISSION) 으로 분류.\n"
         "출력: FileSequence 리스트 (calls + dimensions)", 94.0),
        ("input: detected capability\n"
         "L2 가 추출한 dimensions 가 매니페스트 declared 와 비교될 detected 입력.", 50.0),
    ], row_colors={3: C_MANIFEST})

    # L3
    table_row(pdf, [
        ("L3", 8.0),
        ("공격 수법 매칭", 30.0),
        ("입력: FileSequence (L2 출력)\n"
         "처리: (a) MITRE ATT&CK Enterprise 568 TTP 임베딩 (sentence-transformer "
         "MiniLM-L6) cosine top-K. (b) 47-indicator (Unveiling Malicious Logic 2025) "
         "statement-level 매칭. (c) taint slicing (Taint-Based Slicing 2025) "
         "오염 dataflow 추적.\n"
         "출력: TTPMatch 리스트 (ttp_id + severity + similarity)", 94.0),
        ("input: detected TTPs\n"
         "TTP 매칭 결과가 매니페스트 declared capability 집합과 diff. "
         "미선언 위험 TTP 발견 시 격상 신호.", 50.0),
    ], row_colors={3: C_MANIFEST})

    # L4
    table_row(pdf, [
        ("L4", 8.0),
        ("LLM 의미 재검토", 30.0),
        ("입력: TTPMatch + source snippets (L2·L3 출력)\n"
         "처리: Claude 3-agent — semantic (의미 검증) · diff (버전 간 변화) · "
         "dependency (의존성 그래프 의미). 각 agent 가 verdict + confidence 보고.\n"
         "출력: LLM verdict (BENIGN/SUSPICIOUS/MALICIOUS) + self-confidence", 94.0),
        ("병렬 검증 layer\n"
         "LLM 의미 검증과 매니페스트 선언 검증은 *직교* — LLM 이 BENIGN 으로 봐도 "
         "매니페스트 diff 가 미선언 capability 잡으면 격상.", 50.0),
    ], row_colors={3: C_MANIFEST})

    # L5
    table_row(pdf, [
        ("L5", 8.0),
        ("의존성·바이너리·샌드박스", 30.0),
        ("입력: 패키지 + dependency list\n"
         "처리: (a) 의존성 재귀 (최대 깊이 N). (b) pefile (Windows PE) / "
         "pyelftools (Linux ELF) 로 import / 심볼 분석. (c) Docker 샌드박스 "
         "(cap-drop ALL + no-new-privileges + pids/memory/cpu 제한) 옵션.\n"
         "출력: 의존성 트리 + 바이너리 import 목록 + 동적 행위 trace", 94.0),
        ("—  (바이너리 / 동적 분석은 매니페스트와 분리)", 50.0),
    ], row_colors={3: C_MUTED})

    # L6
    table_row(pdf, [
        ("L6", 8.0),
        ("판정 + 표준 출력", 30.0),
        ("입력: Evidence 리스트 (L0~L5 + 매니페스트 diff)\n"
         "처리: verdict_rules.py 결정 트리 (§2 참조). 출력 어댑터로 STIX 2.1 / "
         "TAXII 2.1 / Falco rule / CycloneDX VEX / SLSA provenance / HMAC webhook.\n"
         "출력: Verdict (MALICIOUS / HIGH_RISK / SUSPICIOUS / CLEAN / ERROR / "
         "CANNOT_ANALYZE) + 표준 sink", 94.0),
        ("output: manifest diff 반영\n"
         "매니페스트 diff 결과 (undeclared dangerous capability 발견 여부) 가 "
         "verdict 격상 입력으로 들어감.", 50.0),
    ], row_colors={3: C_MANIFEST})

    # 매니페스트 별도 행 (직교 layer)
    pdf.ln(1)
    body(pdf,
         "직교 검증 layer — Agentic Capability Manifest",
         bold=True, color=C_MANIFEST, size=10.5)
    body(pdf,
         "패키지 작성자가 pyproject.toml 의 [tool.agentic] 섹션 "
         "(또는 npm package.json 의 agentic 필드) 에 자신이 사용할 위험 capability "
         "(예: net.http, shell.exec, fs.read, secrets.read) 를 사전 선언. "
         "L2/L3 의 detected capability 와 declared 의 차집합 "
         "(undeclared dangerous capability) 을 계산해 verdict 격상에 사용.",
         color=C_INK, size=9.5)
    body(pdf,
         "구현 위치: src/pkgsentinel/agentic/classifier.py "
         "(Step 1~4 결정 트리 — manifest parse / capability extraction / "
         "Rule of Two / R1-R4 룰).",
         color=C_MUTED, size=9)

    # ─── §2. MALICIOUS 판정 기준 ─────────────────
    section(pdf, "2. MALICIOUS 판정 기준 (verdict_rules.py 현재 코드)")

    body(pdf,
         "MALICIOUS 는 가장 엄격한 verdict. 다음 3 조건 모두 만족 (AND) 해야 진입. "
         "하나라도 모자라면 자동으로 HIGH_RISK 이하로 강등.",
         size=10)
    pdf.ln(0.5)

    # MALICIOUS 3-AND 박스
    pdf.set_fill_color(*C_LIGHT)
    pdf.set_font("Malgun", "B", 10.5)
    pdf.set_text_color(*C_INK)
    pdf.multi_cell(0, 6.5,
                   "  MALICIOUS   =   high-severity TTP evidence ≥ 1   "
                   "AND   LLM verdict ∈ MALICIOUS   "
                   "AND   max(MALICIOUS evidence confidence) ≥ 0.85",
                   fill=True)
    pdf.ln(0.5)

    kv(pdf, "① high-severity TTP",
       "L3 (Stage 11) TTP 매칭 중 severity = HIGH 가 1개 이상.")
    kv(pdf, "② LLM MALICIOUS",
       "L4 (Stage 16) Claude 3-agent 중 1개라도 MALICIOUS 답.")
    kv(pdf, "③ max conf ≥ 0.85",
       "위 LLM MALICIOUS evidence 중 가장 신뢰도 높은 것의 self-reported "
       "confidence (Claude 응답).")

    pdf.ln(0.8)
    body(pdf,
         "※ confidence 기준이 전체 평균이 아닌 max (H-6 fix). 평균을 쓰면 진짜 "
         "exfil 체인에 저신뢰 잡음 1건만 섞여도 평균이 깎여 MALICIOUS → HIGH_RISK "
         "로 강등되던 버그를 외부 코드리뷰에서 발견 후 수정 (commit f4debf8). "
         "회귀 테스트 포함.",
         color=C_MUTED, size=9)

    pdf.ln(1)
    body(pdf, "Verdict 결정 트리 (전체)", bold=True, color=C_NAVY, size=10.5)

    cols_v = [
        ("Verdict", 30.0),
        ("판정 조건", 152.0),
    ]
    table_header(pdf, cols_v, h=6.5, fontsize=9.5)

    table_row(pdf, [
        ("MALICIOUS", 30.0),
        ("high-severity TTP ≥ 1   AND   LLM ∋ MALICIOUS   AND   "
         "max(LLM MALICIOUS confidence) ≥ 0.85", 152.0),
    ], row_fonts={0: ("B", 9)},
       row_colors={0: (192, 57, 43)})

    table_row(pdf, [
        ("HIGH_RISK", 30.0),
        ("(strong TTP match similarity ≥ 0.85   OR   version_diff critical)   "
         "AND   LLM verdict ∈ {SUSPICIOUS, MALICIOUS}", 152.0),
    ], row_fonts={0: ("B", 9)},
       row_colors={0: (212, 122, 31)})

    table_row(pdf, [
        ("SUSPICIOUS", 30.0),
        ("weak TTP match (similarity 0.70~0.85, LLM ≠ BENIGN)   OR   "
         "version_diff any   OR   LLM SUSPICIOUS evidence ≥ 2 (quorum)", 152.0),
    ], row_fonts={0: ("B", 9)},
       row_colors={0: (218, 165, 32)})

    table_row(pdf, [
        ("CLEAN", 30.0),
        ("위 어디에도 안 걸림. weak TTP + LLM=BENIGN 인 경우 BENIGN 이 덮어씀.",
         152.0),
    ], row_fonts={0: ("B", 9)},
       row_colors={0: (46, 164, 79)})

    table_row(pdf, [
        ("ERROR", 30.0),
        ("필수 stage (08 Behavior · 11 TTP · 16 LLM) 중 1개 이상 실패. "
         "부분 판정 금지 — false negative 회피.", 152.0),
    ], row_fonts={0: ("B", 9)},
       row_colors={0: C_MUTED})

    table_row(pdf, [
        ("CANNOT_ANALYZE", 30.0),
        ("Stage 00 에서 레지스트리 미등록 확정 또는 추출 가능한 source 파일 부재.",
         152.0),
    ], row_fonts={0: ("B", 9)},
       row_colors={0: C_MUTED})

    pdf.ln(1)
    body(pdf, "설계 원칙 (verdict_rules.py 주석 인용)", bold=True, color=C_NAVY, size=10.5)
    kv(pdf, "Trust by Verification",
       "패키지 나이 · 인기도 · 다운로드 수 일절 미참조. 유명 패키지 감염 (Shai-Hulud 등) 회피.")
    kv(pdf, "부분 판정 금지",
       "필수 stage 중 1개라도 실패 시 ERROR. 분석 불완전 시 false negative 차단.")
    kv(pdf, "BENIGN 덮어쓰기",
       "LLM 이 BENIGN 으로 본 weak TTP 매칭은 SUSPICIOUS 로 승격 안 됨. FP 억제.")
    kv(pdf, "max(conf) ≥ 0.85",
       "H-6 fix. 평균이 아닌 가장 강한 단일 악성 증거 기준. 잡음 evidence 가 섞여도 강등 방지.")
    kv(pdf, "LLM-only quorum = 2",
       "단일 LLM 의심 evidence 로는 SUSPICIOUS 승격 안 함. 대량 분석 FP 누적 억제.")

    pdf.ln(0.5)
    body(pdf,
         "임계값 — strong TTP similarity 0.85 / weak TTP 0.70 / "
         "MALICIOUS confidence 0.85 / LLM quorum 2.",
         color=C_MUTED, size=9)

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
                   "참고 코드: "
                   "src/pkgsentinel/verdict_rules.py (메인 결정), "
                   "src/pkgsentinel/stages/stage4_ttp_match.py (TTP 임베딩), "
                   "src/pkgsentinel/stages/stage4_rules.py (규칙 기반 매칭), "
                   "src/pkgsentinel/stages/stage5_multi_agent.py (LLM 3-agent), "
                   "src/pkgsentinel/agentic/classifier.py (매니페스트 diff).")

    pdf.output(str(OUT))
    print(f"Wrote: {OUT}  ({OUT.stat().st_size // 1024} KB, {pdf.page_no()} pages)")


if __name__ == "__main__":
    build()
