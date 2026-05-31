"""pkgsentinel 시스템 구조도 v2 — 5개 논리 계층 (레벨 통일).

교수님 #6 지적 응답:
  이전 버전: py(pipeline.py) / API(Claude) / DB(SQLCipher) / 인터페이스(HTTP API)
            / 도구(CLI/Extension) 가 같은 레벨로 혼재.
  v2:        5개 *논리 계층* 으로 통일. 각 박스는 *역할* 만, 기술 스택은
            박스 안 작은 라벨로 부기.

5 계층 (위→아래):
  1. Client Layer    — 사용자가 닿는 표면 (CLI · IDE/Browser Ext · REST)
  2. Analysis Layer  — 7-layer detection backend (Static · Behavior · LLM)
  3. Knowledge Layer — Threat Intel · Embeddings · Encrypted Cache
  4. Decision Layer  — Rule Engine + Agentic Manifest Diff (직교 검증)
  5. Reporting Layer — 표준 출력 어댑터 (SBOM/VEX · STIX · SIEM · SLSA)

출력: docs/pkgsentinel_system_diagram.png
"""
from __future__ import annotations

from pathlib import Path

import matplotlib.font_manager as fm
import matplotlib.patches as mpatches
import matplotlib.pyplot as plt
from matplotlib import rcParams
from matplotlib.patches import FancyArrowPatch, FancyBboxPatch

# 한글 폰트
FONT_PATH = r"C:\Windows\Fonts\malgun.ttf"
fm.fontManager.addfont(FONT_PATH)
KO_FONT = fm.FontProperties(fname=FONT_PATH).get_name()
rcParams["font.family"] = KO_FONT
rcParams["axes.unicode_minus"] = False

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "docs" / "pkgsentinel_system_diagram.png"

# 색상 팔레트 — prof brief 와 통일
C_BG = "#FFFFFF"
C_INK = "#14233A"
C_MUTED = "#6A7C8C"

# 계층별 fill / border
C_CLIENT_BG  = "#E8F0F8"; C_CLIENT_BD  = "#4A78B0"
C_ANALYSIS_BG = "#D9E7FF"; C_ANALYSIS_BD = "#3D6FCC"
C_KNOWLEDGE_BG = "#D6F2DD"; C_KNOWLEDGE_BD = "#3FA85F"
C_DECISION_BG = "#E3D6FF"; C_DECISION_BD = "#6A3FBF"
C_REPORT_BG = "#FFD9D9"; C_REPORT_BD = "#C0392B"

# 매니페스트 강조
C_MANIFEST = "#6A3FBF"

C_ARROW = "#2D3B5F"
C_LAYER_LABEL = "#9AA0A6"


# ─────────────── helpers ───────────────

def layer_band(ax, x, y, w, h, *, name, bg, bd):
    """계층 밴드 (배경 사각형)."""
    rect = FancyBboxPatch(
        (x, y), w, h,
        boxstyle="round,pad=0.02,rounding_size=0.10",
        linewidth=1.2, edgecolor=bd, facecolor=bg, alpha=0.4,
    )
    ax.add_patch(rect)
    # 좌측 계층 라벨
    ax.text(x + 0.18, y + h - 0.32, name,
            fontsize=11, color=bd, fontweight="bold")


def role_box(ax, x, y, w, h, *, role, tech, bd):
    """역할 박스 (역할 명 + 작은 기술 라벨)."""
    rect = FancyBboxPatch(
        (x, y), w, h,
        boxstyle="round,pad=0.02,rounding_size=0.10",
        linewidth=1.4, edgecolor=bd, facecolor="white",
    )
    ax.add_patch(rect)
    ax.text(x + w/2, y + h*0.62, role,
            ha="center", va="center", fontsize=14, fontweight="bold",
            color=C_INK)
    ax.text(x + w/2, y + h*0.28, tech,
            ha="center", va="center", fontsize=9.5, color=C_MUTED,
            style="italic")


def arrow(ax, x1, y1, x2, y2, *, color=C_ARROW, lw=1.6, style="-",
          mutation=14):
    a = FancyArrowPatch(
        (x1, y1), (x2, y2),
        arrowstyle="-|>", mutation_scale=mutation,
        linestyle=style, linewidth=lw, color=color,
        shrinkA=2, shrinkB=2,
    )
    ax.add_patch(a)


def double_arrow(ax, x1, y1, x2, y2, *, color=C_ARROW, lw=1.6):
    """양방향 화살표 (Knowledge ↔ Analysis 같은 lookup)."""
    a = FancyArrowPatch(
        (x1, y1), (x2, y2),
        arrowstyle="<|-|>", mutation_scale=14,
        linewidth=lw, color=color,
        shrinkA=2, shrinkB=2,
    )
    ax.add_patch(a)


# ─────────────── main ───────────────

def main():
    fig, ax = plt.subplots(figsize=(14, 11), dpi=160)
    ax.set_xlim(0, 14)
    ax.set_ylim(0, 11.5)
    ax.set_facecolor(C_BG)
    ax.axis("off")

    # 제목
    ax.text(7, 11.15, "pkgsentinel 시스템 구조 (5-layer)",
            ha="center", va="center", fontsize=22, fontweight="bold",
            color=C_INK)
    ax.text(7, 10.78,
            "역할 단위로 통일된 논리 계층 — 기술 스택은 박스 안 라벨로 부기",
            ha="center", va="center", fontsize=11, color=C_MUTED,
            style="italic")

    # ───── 계층 좌표 (위→아래) ─────
    LX = 0.4; LW = 13.2

    # 1. Client Layer
    y1, h1 = 8.95, 1.30
    layer_band(ax, LX, y1, LW, h1,
               name="Client Layer", bg=C_CLIENT_BG, bd=C_CLIENT_BD)
    role_box(ax, 1.8, y1+0.18, 3.0, 0.85,
             role="CLI",
             tech="pkgsentinel command",
             bd=C_CLIENT_BD)
    role_box(ax, 5.5, y1+0.18, 3.0, 0.85,
             role="IDE / Browser Ext",
             tech="VSCode · Chrome",
             bd=C_CLIENT_BD)
    role_box(ax, 9.2, y1+0.18, 3.0, 0.85,
             role="REST API",
             tech="FastAPI (HTTP)",
             bd=C_CLIENT_BD)

    # 2. Analysis Layer
    y2, h2 = 6.85, 1.80
    layer_band(ax, LX, y2, LW, h2,
               name="Analysis Layer — 7-layer detection backend",
               bg=C_ANALYSIS_BG, bd=C_ANALYSIS_BD)
    role_box(ax, 1.0, y2+0.30, 3.5, 1.10,
             role="Static Analysis",
             tech="AST · tree-sitter · taint slicing",
             bd=C_ANALYSIS_BD)
    role_box(ax, 5.25, y2+0.30, 3.5, 1.10,
             role="Behavioral Analysis",
             tech="MITRE TTP 임베딩 + 47-indicator",
             bd=C_ANALYSIS_BD)
    role_box(ax, 9.5, y2+0.30, 3.5, 1.10,
             role="LLM Verification",
             tech="Claude 3-agent (의미·diff·dep)",
             bd=C_ANALYSIS_BD)

    # 3. Knowledge Layer
    y3, h3 = 4.85, 1.70
    layer_band(ax, LX, y3, LW, h3,
               name="Knowledge Layer — 위협 인텔리전스 / 임베딩 / 캐시",
               bg=C_KNOWLEDGE_BG, bd=C_KNOWLEDGE_BD)
    role_box(ax, 1.0, y3+0.28, 3.5, 1.05,
             role="Threat Intel DB",
             tech="OSV + OSSF malicious-packages",
             bd=C_KNOWLEDGE_BD)
    role_box(ax, 5.25, y3+0.28, 3.5, 1.05,
             role="Embeddings",
             tech="MITRE ATT&CK 568 TTP",
             bd=C_KNOWLEDGE_BD)
    role_box(ax, 9.5, y3+0.28, 3.5, 1.05,
             role="Encrypted Cache",
             tech="SQLCipher (AES-256)",
             bd=C_KNOWLEDGE_BD)

    # 4. Decision Layer
    y4, h4 = 2.85, 1.70
    layer_band(ax, LX, y4, LW, h4,
               name="Decision Layer — 판정 + 매니페스트 검증 (직교)",
               bg=C_DECISION_BG, bd=C_DECISION_BD)
    role_box(ax, 1.6, y4+0.30, 4.8, 1.05,
             role="Rule Engine",
             tech="verdict_rules (3-AND, threshold)",
             bd=C_DECISION_BD)
    role_box(ax, 7.0, y4+0.30, 5.4, 1.05,
             role="Agentic Manifest Diff  ★",
             tech="declared (pyproject [tool.agentic]) vs detected",
             bd=C_MANIFEST)

    # 5. Reporting Layer
    y5, h5 = 0.85, 1.70
    layer_band(ax, LX, y5, LW, h5,
               name="Reporting Layer — 표준 출력 어댑터",
               bg=C_REPORT_BG, bd=C_REPORT_BD)
    role_box(ax, 0.7, y5+0.28, 3.0, 1.05,
             role="SBOM / VEX",
             tech="CycloneDX",
             bd=C_REPORT_BD)
    role_box(ax, 3.9, y5+0.28, 3.0, 1.05,
             role="STIX 2.1",
             tech="MITRE ATT&CK + TAXII",
             bd=C_REPORT_BD)
    role_box(ax, 7.1, y5+0.28, 3.0, 1.05,
             role="SIEM Webhook",
             tech="HMAC signed · Falco rule",
             bd=C_REPORT_BD)
    role_box(ax, 10.3, y5+0.28, 3.0, 1.05,
             role="SLSA",
             tech="provenance",
             bd=C_REPORT_BD)

    # ───── 계층 간 화살표 (데이터 흐름) ─────

    # Client → Analysis (3개)
    for cx in [3.3, 7.0, 10.7]:
        arrow(ax, cx, y1+0.18, cx, y2+h2-0.05, color=C_CLIENT_BD, lw=1.4)

    # Analysis → Decision (단방향, evidence 전달)
    arrow(ax, 2.75, y2+0.30, 4.0, y4+h4-0.05, color=C_ANALYSIS_BD, lw=1.4)
    arrow(ax, 7.0,  y2+0.30, 4.0, y4+h4-0.05, color=C_ANALYSIS_BD, lw=1.4)
    arrow(ax, 11.25, y2+0.30, 4.0, y4+h4-0.05, color=C_ANALYSIS_BD, lw=1.4)

    # Behavioral + LLM → Manifest Diff (detected capability 입력)
    arrow(ax, 7.5, y2+0.30, 9.7, y4+h4-0.05,
          color=C_MANIFEST, lw=1.4)
    arrow(ax, 11.0, y2+0.30, 9.7, y4+h4-0.05,
          color=C_MANIFEST, lw=1.4)

    # Knowledge ↔ Analysis (양방향 lookup)
    double_arrow(ax, 2.75, y3+h3-0.10, 2.75, y2+0.05,
                 color=C_KNOWLEDGE_BD, lw=1.4)
    double_arrow(ax, 7.0, y3+h3-0.10, 7.0, y2+0.05,
                 color=C_KNOWLEDGE_BD, lw=1.4)
    double_arrow(ax, 11.25, y3+h3-0.10, 11.25, y2+0.05,
                 color=C_KNOWLEDGE_BD, lw=1.4)

    # Decision → Reporting
    arrow(ax, 4.0, y4+0.30, 4.0, y5+h5-0.05, color=C_DECISION_BD, lw=1.4)
    arrow(ax, 9.7, y4+0.30, 9.7, y5+h5-0.05, color=C_DECISION_BD, lw=1.4)

    # ───── 범례 (하단) ─────
    legend_items = [
        ("Client",    C_CLIENT_BD),
        ("Analysis",  C_ANALYSIS_BD),
        ("Knowledge", C_KNOWLEDGE_BD),
        ("Decision",  C_DECISION_BD),
        ("Reporting", C_REPORT_BD),
        ("★ Manifest layer (직교)", C_MANIFEST),
    ]
    handles = [mpatches.Patch(facecolor="white", edgecolor=c,
                              linewidth=1.6, label=name)
               for name, c in legend_items]
    ax.legend(handles=handles, loc="lower center",
              bbox_to_anchor=(0.5, -0.03), ncol=6, frameon=False,
              fontsize=9.5)

    plt.tight_layout()
    OUT.parent.mkdir(parents=True, exist_ok=True)
    plt.savefig(str(OUT), bbox_inches="tight", facecolor=C_BG, dpi=200)
    plt.close()
    print(f"Wrote: {OUT}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
