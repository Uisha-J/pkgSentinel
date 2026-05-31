"""pkgsentinel C4 Container 다이어그램 (Omar Ismail 글 / C4 model 원칙).

원칙: 외부 액터·시스템 명시 + 시스템 경계 + 프로토콜 라벨된 데이터 흐름.
산출: docs/pkgsentinel_c4_container.png
"""
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch, FancyArrowPatch
plt.rcParams["font.family"] = "Malgun Gothic"
plt.rcParams["axes.unicode_minus"] = False

NAVY = "#1B2A4A"; BLUE = "#1168BD"; TEAL = "#1C7293"; MINT = "#0B6E5A"
GRAY = "#8895A7"; GRAYD = "#5B6677"; AMBER = "#B9791F"; PAPER = "#FFFFFF"
LINE = "#9AA7BC"

fig, ax = plt.subplots(figsize=(15, 9.2))
ax.set_xlim(0, 15); ax.set_ylim(0, 9.2); ax.axis("off")


def box(x, y, w, h, title, tech="", desc="", fill=BLUE, tcol="white", style="round"):
    bs = "round,pad=0.02,rounding_size=0.10" if style == "round" else "square,pad=0.02"
    ax.add_patch(FancyBboxPatch((x, y), w, h, boxstyle=bs, linewidth=1.2,
                 edgecolor="#0D4C8B" if fill == BLUE else "#3A4D6B",
                 facecolor=fill, zorder=3))
    cx = x + w / 2
    ax.text(cx, y + h - 0.26, title, ha="center", va="top", fontsize=10.5,
            fontweight="bold", color=tcol, zorder=4)
    yy = y + h - 0.52
    if tech:
        ax.text(cx, yy, tech, ha="center", va="top", fontsize=7.3,
                color=tcol, style="italic", zorder=4)
        yy -= 0.24
    if desc:
        ax.text(cx, yy, desc, ha="center", va="top", fontsize=7.6,
                color=tcol, zorder=4, wrap=True)


def actor(x, y, name, desc):
    # person: head + body box
    ax.add_patch(plt.Circle((x + 0.55, y + 0.95), 0.17, facecolor=NAVY, edgecolor="none", zorder=4))
    ax.add_patch(FancyBboxPatch((x, y), 1.1, 0.78, boxstyle="round,pad=0.02,rounding_size=0.08",
                 linewidth=1.2, edgecolor="#14223B", facecolor=NAVY, zorder=3))
    ax.text(x + 0.55, y + 0.5, name, ha="center", va="center", fontsize=9.2, fontweight="bold", color="white", zorder=4)
    ax.text(x + 0.55, y + 0.18, desc, ha="center", va="center", fontsize=6.8, color="#CADCFC", zorder=4)


def arrow(p1, p2, label="", color=GRAYD, rad=0.0, ls="-", lx=None, ly=None, fs=7.2):
    ax.add_patch(FancyArrowPatch(p1, p2, connectionstyle=f"arc3,rad={rad}",
                 arrowstyle="-|>", mutation_scale=12, linewidth=1.1,
                 color=color, linestyle=ls, zorder=2))
    if label:
        mx = lx if lx is not None else (p1[0] + p2[0]) / 2
        my = ly if ly is not None else (p1[1] + p2[1]) / 2
        ax.text(mx, my, label, ha="center", va="center", fontsize=fs, color=GRAYD,
                bbox=dict(boxstyle="round,pad=0.15", fc="white", ec="none", alpha=0.9), zorder=5)


# ── 제목 ──
ax.text(7.5, 8.95, "pkgsentinel — 시스템 구조 (C4 Container)", ha="center", fontsize=16, fontweight="bold", color=NAVY)
ax.text(7.5, 8.62, "외부 액터·시스템 + 시스템 경계 + 프로토콜 라벨된 데이터 흐름", ha="center", fontsize=9.5, color="#6B7A99", style="italic")

# ── 액터 (왼쪽) ──
actor(0.3, 6.7, "개발자", "패키지 검사")
actor(0.3, 5.2, "CI/CD", "파이프라인 게이트")
actor(0.3, 0.55, "보안 분석가", "SIEM 수신")

# ── 시스템 경계 ──
ax.add_patch(FancyBboxPatch((2.35, 0.45), 8.05, 7.55, boxstyle="round,pad=0.02,rounding_size=0.06",
             linewidth=1.6, edgecolor=BLUE, facecolor="#F2F7FD", linestyle=(0, (6, 4)), zorder=1))
ax.text(2.5, 7.78, "pkgsentinel  [Software System]", fontsize=10, fontweight="bold", color=BLUE)

# 클라이언트 컨테이너 (상단)
box(2.6, 6.7, 2.35, 1.0, "CLI", "Python", "pkgsentinel check")
box(5.18, 6.7, 2.35, 1.0, "REST API", "FastAPI · HTTP", "/analyze /runtime-alert")
box(7.76, 6.7, 2.45, 1.0, "IDE / Browser Ext", "VSCode · Chrome MV3", "실시간 인라인 경고")

# 분석 엔진 (중앙 핵심)
box(3.5, 4.65, 5.6, 1.45, "Analysis Engine", "7계층 / 21단계 파이프라인",
    "정적(AST·taint) · 행위(MITRE TTP·47-indicator) · LLM 검증", fill=TEAL)

# 지식 저장소
box(2.6, 3.0, 2.35, 1.15, "Threat Intel DB", "OSV · OSSF", "known-malicious", fill="#2C5F5A")
box(5.18, 3.0, 2.35, 1.15, "TTP Embeddings", "MiniLM · 568 TTP", "cosine 매칭", fill="#2C5F5A")
box(7.76, 3.0, 2.45, 1.15, "Encrypted Cache", "SQLCipher AES-256", "분석 결과", fill="#2C5F5A")

# 판정
box(3.1, 1.66, 3.3, 0.98, "Rule Engine", "verdict_rules", "3-AND · threshold", fill="#7A5C1E")
box(6.7, 1.66, 3.5, 0.98, "Agentic Manifest Diff  ★", "declared vs detected", "미선언 권한 경고", fill="#7A5C1E")

# 출력 어댑터 (제목/본문 별도 라인)
ax.add_patch(FancyBboxPatch((2.6, 0.56), 7.6, 0.92, boxstyle="round,pad=0.02,rounding_size=0.08",
             linewidth=1.2, edgecolor="#3A4D6B", facecolor="#5B6677", zorder=3))
ax.text(6.4, 1.27, "Output Adapters  [표준 출력 어댑터]", ha="center", va="center",
        fontsize=9.3, fontweight="bold", color="white", zorder=4)
ax.text(6.4, 0.84, "SBOM/VEX (CycloneDX) · STIX 2.1/TAXII · SIEM Webhook (HMAC) · SLSA",
        ha="center", va="center", fontsize=7.8, color="#E5E9F0", zorder=4)

# ── 외부 시스템 (오른쪽) ──
box(11.7, 6.7, 3.0, 1.0, "PyPI / npm Registry", "공개 레지스트리", "패키지 아카이브", fill=GRAY, tcol="white")
box(11.7, 5.25, 3.0, 1.0, "OSV / OSSF Feeds", "Google · OpenSSF", "악성·취약 인텔", fill=GRAY)
box(11.7, 3.8, 3.0, 1.0, "Anthropic Claude API", "LLM", "3-agent 검증", fill=GRAY)
box(11.7, 2.35, 3.0, 1.0, "MITRE ATT&CK CTI", "STIX 번들", "TTP 코퍼스", fill=GRAY)

# ── 관계 (라벨된 흐름) ──
arrow((1.4, 7.1), (2.6, 7.2), "check <pkg>", lx=2.0, ly=7.45)
arrow((1.5, 5.5), (6.3, 6.7), "POST /analyze [HTTPS]", rad=-0.13, lx=3.4, ly=5.6, fs=7.0)  # CI/CD→REST(CLI 아래로)
arrow((2.6, 0.86), (1.5, 0.9), "HMAC 경보", lx=2.05, ly=1.16, fs=6.9)  # Output → 분석가
# 클라이언트 → 엔진
arrow((3.75, 6.7), (4.6, 6.1), "", rad=0.0)
arrow((6.3, 6.7), (6.3, 6.1), "요청", lx=6.62, ly=6.42)
arrow((8.95, 6.7), (8.2, 6.1), "", rad=0.0)
# 엔진 → 외부 (라벨은 경계~외부박스 gap[10.4~11.7]에 배치)
arrow((9.1, 5.88), (11.7, 7.05), "아카이브 fetch\n[HTTPS·스트림]", rad=0.10, lx=11.0, ly=6.42, fs=6.5)
arrow((9.1, 5.45), (11.7, 5.7), "known-malicious\n조회", rad=0.0, lx=11.0, ly=5.12, fs=6.5)
arrow((9.1, 5.02), (11.7, 4.25), "3-agent review\n[HTTPS/JSON]", rad=-0.08, lx=11.0, ly=4.35, fs=6.5)
arrow((11.7, 2.7), (7.55, 3.45), "TTP 코퍼스\n(build-time)", rad=0.14, lx=10.4, ly=2.42, fs=6.5, color=GRAY, ls="--")
# 엔진 → 지식 (짧게 아래로)
arrow((4.5, 4.65), (3.8, 4.15), "", rad=0.0)
arrow((6.3, 4.65), (6.3, 4.15), "read / write", lx=6.82, ly=4.42, fs=6.8)
arrow((8.6, 4.65), (8.9, 4.15), "", rad=0.0)
# 엔진 → 판정 (지식 박스 사이 채널 통과)
arrow((5.06, 4.6), (4.75, 2.64), "evidence·\nindicators", rad=0.0, lx=3.85, ly=2.83, fs=6.6)
arrow((7.64, 4.6), (8.45, 2.64), "", rad=0.0)
# 판정 → 출력
arrow((4.75, 1.66), (4.75, 1.48), "", rad=0.0)
arrow((8.45, 1.66), (8.45, 1.48), "verdict", lx=8.92, ly=1.57, fs=6.8)

# ── 범례 ──
import matplotlib.patches as mp
leg = [("액터(Person)", NAVY), ("내부 컨테이너", TEAL), ("외부 시스템", GRAY), ("★ Manifest layer", "#7A5C1E")]
x0 = 2.6
for name, c in leg:
    ax.add_patch(mp.Rectangle((x0, 0.05), 0.22, 0.16, facecolor=c, edgecolor="none"))
    ax.text(x0 + 0.3, 0.13, name, fontsize=7.5, va="center", color="#444")
    x0 += 2.2

plt.tight_layout()
out = "docs/pkgsentinel_c4_container.png"
plt.savefig(out, dpi=150, bbox_inches="tight", facecolor="white")
print("saved:", out)
