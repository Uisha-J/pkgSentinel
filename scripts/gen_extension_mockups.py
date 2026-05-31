"""Chrome / VSCode 확장 동작 화면 목업 (matplotlib).

실제 확장은 아직 구현 전 (TODO). 발표용으로 "이렇게 보일 것이다"를
보여주기 위한 정적 목업 이미지를 생성한다.

출력:
  docs/mockup_chrome_extension.png  — claude.ai 응답에 인라인 뱃지 + 패널
  docs/mockup_vscode_extension.png  — requirements.txt diagnostic + hover

설계 원칙:
  - 한 장으로 "무엇을 어디서 본다" 가 즉시 이해되어야 함
  - 실제 UI 와 톤만 맞추면 충분 (픽셀 단위 X)
"""
from __future__ import annotations

from pathlib import Path

import matplotlib.font_manager as fm
import matplotlib.patches as mpatches
import matplotlib.pyplot as plt
from matplotlib import rcParams
from matplotlib.patches import FancyArrowPatch, FancyBboxPatch, Rectangle

FONT_PATH = r"C:\Windows\Fonts\malgun.ttf"
FONT_MONO = r"C:\Windows\Fonts\consola.ttf"
fm.fontManager.addfont(FONT_PATH)
fm.fontManager.addfont(FONT_MONO)
KO_FONT = fm.FontProperties(fname=FONT_PATH).get_name()
MONO = fm.FontProperties(fname=FONT_MONO).get_name()
rcParams["font.family"] = KO_FONT
rcParams["axes.unicode_minus"] = False

ROOT = Path(__file__).resolve().parent.parent
OUT_DIR = ROOT / "docs"

# 공통 팔레트
C_DANGER = "#D7263D"
C_WARN = "#F4A300"
C_OK = "#2EA44F"
C_TEAL = "#1FA98F"
C_INK = "#14233A"
C_MUTED = "#6A7C8C"


def _round(ax, x, y, w, h, *, fc, ec=None, lw=1.0, r=0.02):
    if ec is None:
        ec = fc
    p = FancyBboxPatch(
        (x, y), w, h,
        boxstyle=f"round,pad=0,rounding_size={r}",
        linewidth=lw, edgecolor=ec, facecolor=fc,
    )
    ax.add_patch(p)
    return p


# ──────────────────────────────────────────────────────────────
# 1. Chrome extension on claude.ai
# ──────────────────────────────────────────────────────────────

def chrome_mockup():
    fig, ax = plt.subplots(figsize=(14, 9), dpi=160)
    ax.set_xlim(0, 14)
    ax.set_ylim(0, 9)
    ax.axis("off")
    ax.set_facecolor("#F5F6F8")

    # 브라우저 외곽
    _round(ax, 0.3, 0.3, 13.4, 8.4, fc="#FFFFFF", ec="#D5DAE0", lw=1.2, r=0.18)
    # 크롬 타이틀바
    _round(ax, 0.3, 7.95, 13.4, 0.75, fc="#E8ECF1", ec="#D5DAE0", lw=1.0, r=0.18)
    for i, c in enumerate(["#FF5F56", "#FFBD2E", "#27C93F"]):
        ax.add_patch(mpatches.Circle((0.65 + i * 0.30, 8.32), 0.10, color=c))
    # 탭
    _round(ax, 1.85, 8.05, 3.5, 0.55, fc="#FFFFFF", ec="#D5DAE0", lw=0.8, r=0.10)
    ax.text(2.05, 8.32, "Claude", fontsize=11, color=C_INK, va="center")
    # URL 바
    _round(ax, 0.5, 7.30, 13.0, 0.55, fc="#F0F2F5", ec="#D5DAE0", lw=0.8, r=0.10)
    ax.text(0.85, 7.57, "https://  claude.ai/chat/abc123", fontsize=11,
            color=C_MUTED, va="center")
    # 확장 아이콘 (URL 바 우측)
    _round(ax, 12.55, 7.34, 0.5, 0.48, fc=C_TEAL, ec=C_TEAL, r=0.10)
    ax.text(12.80, 7.58, "P", fontsize=12, color="white",
            ha="center", va="center", fontweight="bold")
    ax.text(12.80, 7.05, "pkgsentinel", fontsize=8, color=C_MUTED,
            ha="center", va="top")
    # 뱃지 (활성)
    _round(ax, 12.95, 7.65, 0.18, 0.18, fc=C_DANGER, ec=C_DANGER, r=0.05)
    ax.text(13.04, 7.74, "1", fontsize=8, color="white",
            ha="center", va="center", fontweight="bold")

    # ── 대화 영역 ────────────────────────────────────────────
    # 사용자 메시지
    _round(ax, 1.0, 6.20, 11.5, 0.80, fc="#F0F2F5", ec="#E5E8ED", r=0.08)
    ax.text(1.30, 6.60, "User",
            fontsize=10, color=C_MUTED, fontweight="bold")
    ax.text(1.30, 6.30,
            "Write a Python script that scrapes PyPI metadata and stores results in a database.",
            fontsize=11, color=C_INK)

    # AI 응답
    _round(ax, 1.0, 1.50, 11.5, 4.55, fc="#FFFFFF", ec="#E5E8ED", r=0.08)
    ax.text(1.30, 5.85, "Claude",
            fontsize=10, color=C_TEAL, fontweight="bold")
    ax.text(1.30, 5.55, "필요한 패키지를 설치하고 시작해보세요:",
            fontsize=11, color=C_INK)

    # 코드 블록
    _round(ax, 1.30, 4.45, 10.9, 0.95, fc="#1E1F26", ec="#1E1F26", r=0.06)
    ax.text(1.45, 5.18, "bash", fontsize=8, color="#8893A6", family=MONO)
    ax.text(1.45, 4.85, "pip install requests pyppi-scraper",
            fontsize=12, color="#E6E9EF", family=MONO, va="center")
    ax.text(1.45, 4.62, "pip install sqlite-utils",
            fontsize=12, color="#E6E9EF", family=MONO, va="center")

    # 인라인 뱃지 — pyppi-scraper 위
    # 위치: "pyppi-scraper" 글자 끝 부근 (대략 4.10 x ≈ 4.55)
    badge_x, badge_y = 4.50, 4.95
    _round(ax, badge_x, badge_y - 0.04, 1.40, 0.30,
           fc=C_DANGER, ec=C_DANGER, r=0.06)
    ax.text(badge_x + 0.70, badge_y + 0.11, "[!]  MALICIOUS",
            fontsize=9.5, color="white", ha="center", va="center",
            fontweight="bold")
    # 빨간 밑줄 (코드 위)
    ax.plot([3.05, 4.45], [4.78, 4.78], color=C_DANGER, lw=2.0)

    # 텍스트 코멘트
    ax.text(1.30, 4.10,
            "그리고 다음과 같이 사용할 수 있습니다:",
            fontsize=11, color=C_INK)

    # 두 번째 코드 블록 (Python — 클린)
    _round(ax, 1.30, 1.95, 10.9, 2.05, fc="#1E1F26", ec="#1E1F26", r=0.06)
    ax.text(1.45, 3.78, "python", fontsize=8, color="#8893A6", family=MONO)
    lines = [
        ("import requests",                           "#C792EA"),
        ("from pyppi_scraper import PyPIClient",      "#C792EA"),
        ("",                                          "#E6E9EF"),
        ("client = PyPIClient()",                     "#E6E9EF"),
        ("data = client.get_metadata('numpy')",       "#E6E9EF"),
    ]
    for i, (line, _c) in enumerate(lines):
        ax.text(1.45, 3.45 - i * 0.27, line,
                fontsize=11, color="#E6E9EF", family=MONO, va="center")
    # 두 번째 블록에도 pyppi_scraper 밑줄
    ax.plot([2.20, 3.55], [3.18 - 0.10, 3.18 - 0.10], color=C_DANGER, lw=1.6)

    # ── 우측 상단 패널 (확장 팝오버) ─────────────────────────
    panel_x, panel_y, panel_w, panel_h = 8.85, 1.85, 3.10, 3.55
    _round(ax, panel_x, panel_y, panel_w, panel_h,
           fc="#FFFFFF", ec="#C8CFD8", lw=1.2, r=0.10)
    # 패널 헤더
    _round(ax, panel_x, panel_y + panel_h - 0.55, panel_w, 0.55,
           fc=C_INK, ec=C_INK, r=0.10)
    ax.text(panel_x + 0.20, panel_y + panel_h - 0.27,
            "pkgsentinel", fontsize=11, color="white",
            fontweight="bold", va="center")
    ax.text(panel_x + panel_w - 0.20, panel_y + panel_h - 0.27,
            "이 페이지 1건", fontsize=9, color="#A5B0BD",
            ha="right", va="center")

    # 항목 1
    item_y = panel_y + panel_h - 0.95
    _round(ax, panel_x + 0.10, item_y - 0.85, panel_w - 0.20, 0.95,
           fc="#FDECEE", ec="#F0C0C5", r=0.06)
    _round(ax, panel_x + 0.20, item_y - 0.18, 0.95, 0.24,
           fc=C_DANGER, ec=C_DANGER, r=0.04)
    ax.text(panel_x + 0.675, item_y - 0.06, "MALICIOUS",
            fontsize=8, color="white", ha="center", va="center",
            fontweight="bold")
    ax.text(panel_x + 0.20, item_y - 0.40,
            "pyppi-scraper", fontsize=11, color=C_INK,
            fontweight="bold", family=MONO)
    ax.text(panel_x + 0.20, item_y - 0.65,
            "PyPI 미등록 · typosquat 후보",
            fontsize=8.5, color="#8B4046")

    # 항목 1 — 근거
    base = item_y - 1.05
    ax.text(panel_x + 0.20, base,
            "근거", fontsize=9, color=C_INK, fontweight="bold")
    evid = [
        "• 7일 이내 등록 (2026-05-21)",
        "• pypi-scraper 와 편집거리 1",
        "• install_hook + base64_exec",
        "• Author: 신규 계정 (0 prior pkg)",
    ]
    for i, t in enumerate(evid):
        ax.text(panel_x + 0.20, base - 0.27 - i * 0.24, t,
                fontsize=8.5, color=C_INK)

    # 풋터 버튼
    base2 = panel_y + 0.18
    _round(ax, panel_x + 0.20, base2, 1.35, 0.36,
           fc=C_DANGER, ec=C_DANGER, r=0.06)
    ax.text(panel_x + 0.20 + 0.675, base2 + 0.18, "대체안 보기",
            fontsize=9, color="white", ha="center", va="center",
            fontweight="bold")
    _round(ax, panel_x + 1.62, base2, 1.30, 0.36,
           fc="#FFFFFF", ec="#C8CFD8", r=0.06)
    ax.text(panel_x + 1.62 + 0.65, base2 + 0.18, "전체 리포트",
            fontsize=9, color=C_INK, ha="center", va="center")

    # 화살표 (인라인 뱃지 → 패널)
    arr = FancyArrowPatch(
        (5.30, 5.10), (panel_x + 0.10, panel_y + panel_h - 1.20),
        arrowstyle="-|>", mutation_scale=14, lw=1.4,
        color=C_DANGER, connectionstyle="arc3,rad=-0.15",
    )
    ax.add_patch(arr)

    # 캡션
    ax.text(7.0, 0.85,
            "Chrome Extension — AI 응답에서 추천된 패키지명을 실시간 감지 → 인라인 뱃지 + 팝오버 패널",
            fontsize=11.5, color=C_INK, ha="center",
            fontweight="bold")
    ax.text(7.0, 0.55,
            "지원: claude.ai · chatgpt.com · gemini.google.com  ·  로컬 FastAPI(:8001) 호출",
            fontsize=10, color=C_MUTED, ha="center")

    out = OUT_DIR / "mockup_chrome_extension.png"
    plt.tight_layout()
    plt.savefig(out, bbox_inches="tight", facecolor="#F5F6F8", dpi=200)
    plt.close()
    print(f"Wrote: {out}")


# ──────────────────────────────────────────────────────────────
# 2. VSCode extension — requirements.txt
# ──────────────────────────────────────────────────────────────

def vscode_mockup():
    fig, ax = plt.subplots(figsize=(14, 9), dpi=160)
    ax.set_xlim(0, 14)
    ax.set_ylim(0, 9)
    ax.axis("off")
    ax.set_facecolor("#1E1E1E")

    # 타이틀바
    _round(ax, 0, 8.55, 14, 0.45, fc="#3C3C3C", ec="#3C3C3C", r=0)
    ax.text(7, 8.78, "requirements.txt — pkgsentinel-demo — Visual Studio Code",
            fontsize=10, color="#CCCCCC", ha="center", va="center")

    # 액티비티 바 (좌측)
    _round(ax, 0, 0.40, 0.55, 8.15, fc="#333333", ec="#333333", r=0)
    icons = ["Fi", "Sr", "Git", "Db", "Ex", "P"]
    for i, ic in enumerate(icons):
        bg = C_TEAL if ic == "P" else None
        if bg:
            _round(ax, 0.05, 7.95 - i * 0.55, 0.45, 0.45,
                   fc=bg, ec=bg, r=0.04)
        ax.text(0.275, 8.18 - i * 0.55, ic, fontsize=10,
                color="white", ha="center", va="center",
                fontweight="bold")

    # 사이드바 (Explorer)
    _round(ax, 0.55, 0.40, 2.35, 8.15, fc="#252526", ec="#252526", r=0)
    ax.text(0.70, 8.35, "EXPLORER", fontsize=8.5, color="#CCCCCC",
            fontweight="bold")
    ax.text(0.70, 8.05, "v PKGSENTINEL-DEMO", fontsize=9, color="#CCCCCC",
            fontweight="bold")
    files = [
        ("    README.md", "#CCCCCC"),
        ("    main.py", "#CCCCCC"),
        ("    requirements.txt", "#FFFFFF"),  # active
        ("    pyproject.toml", "#CCCCCC"),
    ]
    for i, (name, c) in enumerate(files):
        if name.endswith("requirements.txt"):
            _round(ax, 0.55, 7.65 - i * 0.30 - 0.04, 2.35, 0.28,
                   fc="#37373D", ec="#37373D", r=0)
        ax.text(0.65, 7.65 - i * 0.30 + 0.10, name,
                fontsize=9.5, color=c, va="center")

    # 사이드바 — pkgsentinel 패널 (하단)
    ax.text(0.70, 6.50, "v PKGSENTINEL", fontsize=8.5, color="#CCCCCC",
            fontweight="bold")
    _round(ax, 0.65, 5.95, 2.20, 0.45, fc="#3A1F22", ec="#5C2A30", r=0.04)
    _round(ax, 0.75, 6.05, 0.65, 0.22, fc=C_DANGER, ec=C_DANGER, r=0.04)
    ax.text(0.75 + 0.325, 6.05 + 0.11, "CRIT",
            fontsize=7, color="white", ha="center", va="center",
            fontweight="bold")
    ax.text(1.45, 6.16, "pyppi-scraper",
            fontsize=8.5, color="#FFFFFF", family=MONO, va="center")
    _round(ax, 0.65, 5.50, 2.20, 0.40, fc="#3A2F1A", ec="#5C4A28", r=0.04)
    _round(ax, 0.75, 5.58, 0.65, 0.22, fc=C_WARN, ec=C_WARN, r=0.04)
    ax.text(0.75 + 0.325, 5.58 + 0.11, "WARN",
            fontsize=7, color="white", ha="center", va="center",
            fontweight="bold")
    ax.text(1.45, 5.68, "fast-jsonschma",
            fontsize=8.5, color="#FFFFFF", family=MONO, va="center")

    # 에디터 영역
    edx, edy, edw, edh = 2.90, 2.20, 11.05, 6.30
    _round(ax, edx, edy, edw, edh, fc="#1E1E1E", ec="#1E1E1E", r=0)
    # 탭바
    _round(ax, edx, edy + edh - 0.40, edw, 0.40,
           fc="#2D2D2D", ec="#2D2D2D", r=0)
    _round(ax, edx + 0.10, edy + edh - 0.36, 2.00, 0.36,
           fc="#1E1E1E", ec="#1E1E1E", r=0.02)
    ax.text(edx + 0.30, edy + edh - 0.18, "requirements.txt",
            fontsize=9.5, color="#FFFFFF", va="center")
    ax.text(edx + 1.85, edy + edh - 0.18, "×",
            fontsize=11, color="#CCCCCC", va="center")

    # 라인 번호 + 코드
    lines = [
        "requests>=2.31.0",
        "pyppi-scraper==0.1.2",
        "sqlite-utils>=3.35",
        "fast-jsonschma>=2.0.0",
        "click>=8.1.0",
        "rich>=13.5.0",
    ]
    line_y0 = edy + edh - 0.85
    for i, line in enumerate(lines):
        y = line_y0 - i * 0.36
        # 라인넘버
        ax.text(edx + 0.40, y, str(i + 1),
                fontsize=10, color="#858585", family=MONO,
                ha="right", va="center")
        # 코드
        ax.text(edx + 0.60, y, line,
                fontsize=11.5, color="#D4D4D4", family=MONO, va="center")

    # diagnostic 1 — pyppi-scraper (line 2) 빨간 squiggle
    y2 = line_y0 - 1 * 0.36 - 0.12
    sx, ex = edx + 0.60, edx + 0.60 + 2.30
    # 곡선 대신 짧은 톱니
    xs = []
    ys = []
    n = 36
    for k in range(n + 1):
        x = sx + (ex - sx) * k / n
        xs.append(x)
        ys.append(y2 + (0.04 if k % 2 else -0.04))
    ax.plot(xs, ys, color=C_DANGER, lw=1.2)

    # diagnostic 2 — fast-jsonschma (line 4) 노랑 squiggle (typo)
    y4 = line_y0 - 3 * 0.36 - 0.12
    sx2, ex2 = edx + 0.60, edx + 0.60 + 2.45
    xs2, ys2 = [], []
    for k in range(n + 1):
        x = sx2 + (ex2 - sx2) * k / n
        xs2.append(x)
        ys2.append(y4 + (0.04 if k % 2 else -0.04))
    ax.plot(xs2, ys2, color=C_WARN, lw=1.2)

    # 거터에 마커 (2번줄)
    _round(ax, edx + 0.05, line_y0 - 1 * 0.36 - 0.10, 0.20, 0.20,
           fc=C_DANGER, ec=C_DANGER, r=0.04)
    ax.text(edx + 0.15, line_y0 - 1 * 0.36, "!",
            fontsize=10, color="white", ha="center", va="center",
            fontweight="bold")

    # 호버 팝업 (pyppi-scraper)
    hx, hy, hw, hh = edx + 2.50, edy + 2.30, 5.40, 2.95
    _round(ax, hx, hy, hw, hh, fc="#252526", ec="#454545", lw=1.2, r=0.06)
    # 헤더
    _round(ax, hx, hy + hh - 0.40, hw, 0.40,
           fc="#37373D", ec="#37373D", r=0.06)
    _round(ax, hx + 0.15, hy + hh - 0.32, 0.85, 0.24,
           fc=C_DANGER, ec=C_DANGER, r=0.04)
    ax.text(hx + 0.575, hy + hh - 0.20, "CRITICAL",
            fontsize=7.5, color="white", ha="center", va="center",
            fontweight="bold")
    ax.text(hx + 1.15, hy + hh - 0.20, "pyppi-scraper  v0.1.2",
            fontsize=10, color="#FFFFFF", family=MONO, va="center",
            fontweight="bold")
    ax.text(hx + hw - 0.20, hy + hh - 0.20, "pkgsentinel",
            fontsize=8, color=C_TEAL, ha="right", va="center",
            fontweight="bold")

    # 본문
    lines_h = [
        ("문제", "PyPI 7일 이내 등록 · typosquat 후보", C_DANGER),
        ("탐지", "install_hook (setup.py cmdclass 오버라이드)", "#CCCCCC"),
        ("",     "base64_exec — 인코딩된 페이로드 디코드 → exec()", "#CCCCCC"),
        ("",     "credential_theft — os.environ → HTTP POST", "#CCCCCC"),
        ("유사", "pypi-scraper (편집거리 1, 2.4k weekly downloads)", "#9CDCFE"),
        ("점수", "CRITICAL (rule 0.95 + LLM 0.88, n=3 agent agree)", C_WARN),
    ]
    for i, (k, v, c) in enumerate(lines_h):
        y = hy + hh - 0.75 - i * 0.32
        if k:
            ax.text(hx + 0.20, y, k, fontsize=9, color=C_TEAL,
                    fontweight="bold", va="center")
        ax.text(hx + 0.85, y, v, fontsize=9.5, color=c, va="center")

    # 액션 링크
    ax.text(hx + 0.20, hy + 0.22,
            "Quick Fix...    pypi-scraper로 교체    무시(이 워크스페이스)    상세 리포트",
            fontsize=8.5, color="#3794FF", va="center")

    # 화살표 (squiggle → 팝업)
    arr = FancyArrowPatch(
        (edx + 1.60, y2 - 0.05), (hx + 1.30, hy + hh - 0.10),
        arrowstyle="-|>", mutation_scale=12, lw=1.2,
        color="#888888", connectionstyle="arc3,rad=-0.20",
        linestyle=(0, (3, 3)),
    )
    ax.add_patch(arr)

    # PROBLEMS 패널 (하단)
    _round(ax, edx, edy, edw, 1.30, fc="#1E1E1E", ec="#3C3C3C", lw=1.0, r=0)
    # 탭
    _round(ax, edx, edy + 1.05, edw, 0.25, fc="#252526", ec="#252526", r=0)
    tabs = [("PROBLEMS  2", True), ("OUTPUT", False),
            ("TERMINAL", False), ("DEBUG CONSOLE", False)]
    tx = edx + 0.20
    for label, active in tabs:
        col = "#FFFFFF" if active else "#858585"
        ax.text(tx, edy + 1.17, label, fontsize=8.5, color=col,
                va="center", fontweight="bold" if active else "normal")
        if active:
            ax.plot([tx - 0.05, tx + len(label) * 0.075],
                    [edy + 1.06, edy + 1.06], color=C_TEAL, lw=1.6)
        tx += len(label) * 0.085 + 0.45

    # 항목
    ax.text(edx + 0.20, edy + 0.78,
            "requirements.txt",
            fontsize=8.5, color="#CCCCCC", fontweight="bold")
    _round(ax, edx + 0.30, edy + 0.42, 0.20, 0.20,
           fc=C_DANGER, ec=C_DANGER, r=0.04)
    ax.text(edx + 0.40, edy + 0.52, "!", fontsize=10, color="white",
            ha="center", va="center", fontweight="bold")
    ax.text(edx + 0.60, edy + 0.52,
            "Malicious package: pyppi-scraper (PyPI 미등록 · typosquat)",
            fontsize=9, color="#CCCCCC", va="center")
    ax.text(edx + 7.50, edy + 0.52,
            "pkgsentinel",
            fontsize=8.5, color=C_TEAL, va="center")
    ax.text(edx + 8.60, edy + 0.52,
            "[pkgsentinel/MAL-001]   requirements.txt   2:1",
            fontsize=8.5, color="#858585", va="center", family=MONO)

    _round(ax, edx + 0.30, edy + 0.15, 0.20, 0.20,
           fc=C_WARN, ec=C_WARN, r=0.04)
    ax.text(edx + 0.40, edy + 0.25, "!", fontsize=10, color="white",
            ha="center", va="center", fontweight="bold")
    ax.text(edx + 0.60, edy + 0.25,
            "Possible typosquat: 'fast-jsonschma' → did you mean 'fastjsonschema'?",
            fontsize=9, color="#CCCCCC", va="center")
    ax.text(edx + 7.50, edy + 0.25,
            "pkgsentinel",
            fontsize=8.5, color=C_TEAL, va="center")
    ax.text(edx + 8.60, edy + 0.25,
            "[pkgsentinel/TYPO-002]  requirements.txt   4:1",
            fontsize=8.5, color="#858585", va="center", family=MONO)

    # 상태바 (최하단)
    _round(ax, 0, 0, 14, 0.40, fc=C_TEAL, ec=C_TEAL, r=0)
    ax.text(0.20, 0.20, "git: main", fontsize=9, color="white", va="center")
    ax.text(1.60, 0.20, "[x] 1   [!] 1", fontsize=9, color="white", va="center")
    ax.text(2.80, 0.20, "pkgsentinel: scanned 6 pkgs · 1 critical · 1 warn",
            fontsize=9, color="white", va="center")
    ax.text(13.80, 0.20, "Python 3.12", fontsize=9, color="white",
            va="center", ha="right")

    # 캡션
    ax.text(7.0, 1.85,
            "VSCode Extension — requirements.txt / package.json 저장 시 자동 스캔 → diagnostics + hover + PROBLEMS",
            fontsize=11.5, color="#FFFFFF", ha="center", fontweight="bold")

    out = OUT_DIR / "mockup_vscode_extension.png"
    plt.tight_layout()
    plt.savefig(out, bbox_inches="tight", facecolor="#1E1E1E", dpi=200)
    plt.close()
    print(f"Wrote: {out}")


def main():
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    chrome_mockup()
    vscode_mockup()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
