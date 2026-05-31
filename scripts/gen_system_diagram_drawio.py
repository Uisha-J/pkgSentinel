"""pkgsentinel 시스템 구조도 — drawio (.drawio / .xml) 출력.

matplotlib 버전과 동일 layout. drawio (diagrams.net) 에서 직접 편집 가능.

5 계층:
  Client / Analysis / Knowledge / Decision / Reporting

좌표 변환:
  matplotlib 14 x 11.5 inch → drawio 1400 x 1150 px (factor 100)
  matplotlib y 는 bottom-up, drawio 는 top-down → 변환 필요

출력: docs/pkgsentinel_system_diagram.drawio
"""
from __future__ import annotations

import html
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "docs" / "pkgsentinel_system_diagram.drawio"

# 색상 (matplotlib 버전과 동일)
C_CLIENT_BG  = "#E8F0F8"; C_CLIENT_BD  = "#4A78B0"
C_ANALYSIS_BG = "#D9E7FF"; C_ANALYSIS_BD = "#3D6FCC"
C_KNOWLEDGE_BG = "#D6F2DD"; C_KNOWLEDGE_BD = "#3FA85F"
C_DECISION_BG = "#E3D6FF"; C_DECISION_BD = "#6A3FBF"
C_REPORT_BG = "#FFD9D9"; C_REPORT_BD = "#C0392B"
C_MANIFEST = "#6A3FBF"
C_INK = "#14233A"
C_MUTED = "#6A7C8C"

# 캔버스 크기 (drawio pixel)
CANVAS_W = 1400
CANVAS_H = 1150
SCALE = 100  # 1 inch (matplotlib unit) = 100 px

# matplotlib 11.5 ylim 의 top-down 변환 (matplotlib y → drawio y)
def my(my_y_bottom, h):
    """matplotlib (y=bottom, h) → drawio y_top."""
    return int((11.5 - (my_y_bottom + h)) * SCALE)

def mx(my_x):
    return int(my_x * SCALE)


# ─────────────── cell helpers ───────────────

_id_counter = [10]
def _next_id() -> str:
    _id_counter[0] += 1
    return str(_id_counter[0])


def layer_band(name, mx_x, my_y, mw, mh, *, bg, bd):
    """계층 배경 밴드 + 좌측 라벨."""
    cid = _next_id()
    style = (f"rounded=1;whiteSpace=wrap;html=1;"
             f"fillColor={bg};strokeColor={bd};strokeWidth=2;"
             f"opacity=40;fontSize=12;fontColor={bd};fontStyle=1;"
             f"verticalAlign=top;align=left;spacing=10;")
    return f'''<mxCell id="{cid}" value="{html.escape(name)}" style="{style}" vertex="1" parent="1">
  <mxGeometry x="{mx(mx_x)}" y="{my(my_y, mh)}" width="{mx(mw)}" height="{int(mh*SCALE)}" as="geometry"/>
</mxCell>'''


def role_box(role, tech, mx_x, my_y, mw, mh, *, bd, manifest=False):
    """역할 박스 (역할명 + 기술 라벨)."""
    cid = _next_id()
    # drawio HTML label — 두 줄 (제목 + 작은 부제)
    star = " ★" if manifest else ""
    label = (
        f'<div style="font-size:14px;font-weight:bold;color:{C_INK};">'
        f'{html.escape(role)}{star}</div>'
        f'<div style="font-size:10px;color:{C_MUTED};font-style:italic;'
        f'margin-top:4px;">{html.escape(tech)}</div>'
    )
    # drawio 는 attribute value 안의 HTML 을 escape 필요
    label_escaped = html.escape(label)

    style = (f"rounded=1;whiteSpace=wrap;html=1;fillColor=#FFFFFF;"
             f"strokeColor={bd};strokeWidth=2;fontSize=12;"
             f"verticalAlign=middle;align=center;")
    return f'''<mxCell id="{cid}" value="{label_escaped}" style="{style}" vertex="1" parent="1">
  <mxGeometry x="{mx(mx_x)}" y="{my(my_y, mh)}" width="{mx(mw)}" height="{int(mh*SCALE)}" as="geometry"/>
</mxCell>''', cid


def arrow(src_id, tgt_id, *, color, double=False):
    """source→target edge."""
    cid = _next_id()
    end = "classic" if not double else "classicThin"
    start = "classic" if double else "none"
    style = (f"endArrow={end};html=1;rounded=0;edgeStyle=none;"
             f"strokeColor={color};strokeWidth=2;startArrow={start};"
             f"endFill=1;startFill=1;")
    return f'''<mxCell id="{cid}" style="{style}" edge="1" parent="1" source="{src_id}" target="{tgt_id}">
  <mxGeometry relative="1" as="geometry"/>
</mxCell>'''


# ─────────────── main layout ───────────────

def build_xml() -> str:
    cells = []

    # === 제목 ===
    title_id = _next_id()
    cells.append(f'''<mxCell id="{title_id}" value="pkgsentinel 시스템 구조 (5-layer)" style="text;html=1;align=center;verticalAlign=middle;fontSize=20;fontStyle=1;fontColor={C_INK};" vertex="1" parent="1">
  <mxGeometry x="0" y="20" width="{CANVAS_W}" height="35" as="geometry"/>
</mxCell>''')
    subtitle_id = _next_id()
    cells.append(f'''<mxCell id="{subtitle_id}" value="역할 단위로 통일된 논리 계층 — 기술 스택은 박스 안 라벨로 부기" style="text;html=1;align=center;verticalAlign=middle;fontSize=11;fontStyle=2;fontColor={C_MUTED};" vertex="1" parent="1">
  <mxGeometry x="0" y="58" width="{CANVAS_W}" height="20" as="geometry"/>
</mxCell>''')

    # === 계층 좌표 (matplotlib 단위) ===
    LX = 0.4; LW = 13.2

    # 1. Client Layer
    y1, h1 = 8.95, 1.30
    cells.append(layer_band("Client Layer", LX, y1, LW, h1,
                            bg=C_CLIENT_BG, bd=C_CLIENT_BD))
    cli_box, cli_id = role_box("CLI", "pkgsentinel command",
                                1.8, y1+0.18, 3.0, 0.85, bd=C_CLIENT_BD)
    ext_box, ext_id = role_box("IDE / Browser Ext", "VSCode · Chrome",
                                5.5, y1+0.18, 3.0, 0.85, bd=C_CLIENT_BD)
    rest_box, rest_id = role_box("REST API", "FastAPI (HTTP)",
                                  9.2, y1+0.18, 3.0, 0.85, bd=C_CLIENT_BD)
    cells += [cli_box, ext_box, rest_box]

    # 2. Analysis Layer
    y2, h2 = 6.85, 1.80
    cells.append(layer_band("Analysis Layer — 7-layer detection backend",
                            LX, y2, LW, h2,
                            bg=C_ANALYSIS_BG, bd=C_ANALYSIS_BD))
    stat_box, stat_id = role_box("Static Analysis",
                                  "AST · tree-sitter · taint slicing",
                                  1.0, y2+0.30, 3.5, 1.10, bd=C_ANALYSIS_BD)
    behv_box, behv_id = role_box("Behavioral Analysis",
                                  "MITRE TTP 임베딩 + 47-indicator",
                                  5.25, y2+0.30, 3.5, 1.10, bd=C_ANALYSIS_BD)
    llm_box, llm_id = role_box("LLM Verification",
                                "Claude 3-agent (의미·diff·dep)",
                                9.5, y2+0.30, 3.5, 1.10, bd=C_ANALYSIS_BD)
    cells += [stat_box, behv_box, llm_box]

    # 3. Knowledge Layer
    y3, h3 = 4.85, 1.70
    cells.append(layer_band("Knowledge Layer — 위협 인텔리전스 / 임베딩 / 캐시",
                            LX, y3, LW, h3,
                            bg=C_KNOWLEDGE_BG, bd=C_KNOWLEDGE_BD))
    tdb_box, tdb_id = role_box("Threat Intel DB",
                                "OSV + OSSF malicious-packages",
                                1.0, y3+0.28, 3.5, 1.05, bd=C_KNOWLEDGE_BD)
    emb_box, emb_id = role_box("Embeddings",
                                "MITRE ATT&CK 568 TTP",
                                5.25, y3+0.28, 3.5, 1.05, bd=C_KNOWLEDGE_BD)
    cache_box, cache_id = role_box("Encrypted Cache",
                                    "SQLCipher (AES-256)",
                                    9.5, y3+0.28, 3.5, 1.05, bd=C_KNOWLEDGE_BD)
    cells += [tdb_box, emb_box, cache_box]

    # 4. Decision Layer
    y4, h4 = 2.85, 1.70
    cells.append(layer_band("Decision Layer — 판정 + 매니페스트 검증 (직교)",
                            LX, y4, LW, h4,
                            bg=C_DECISION_BG, bd=C_DECISION_BD))
    rule_box, rule_id = role_box("Rule Engine",
                                  "verdict_rules (3-AND, threshold)",
                                  1.6, y4+0.30, 4.8, 1.05, bd=C_DECISION_BD)
    man_box, man_id = role_box("Agentic Manifest Diff",
                                "declared (pyproject [tool.agentic]) vs detected",
                                7.0, y4+0.30, 5.4, 1.05,
                                bd=C_MANIFEST, manifest=True)
    cells += [rule_box, man_box]

    # 5. Reporting Layer
    y5, h5 = 0.85, 1.70
    cells.append(layer_band("Reporting Layer — 표준 출력 어댑터",
                            LX, y5, LW, h5,
                            bg=C_REPORT_BG, bd=C_REPORT_BD))
    sbom_box, sbom_id = role_box("SBOM / VEX", "CycloneDX",
                                  0.7, y5+0.28, 3.0, 1.05, bd=C_REPORT_BD)
    stix_box, stix_id = role_box("STIX 2.1", "MITRE ATT&CK + TAXII",
                                  3.9, y5+0.28, 3.0, 1.05, bd=C_REPORT_BD)
    siem_box, siem_id = role_box("SIEM Webhook",
                                  "HMAC signed · Falco rule",
                                  7.1, y5+0.28, 3.0, 1.05, bd=C_REPORT_BD)
    slsa_box, slsa_id = role_box("SLSA", "provenance",
                                  10.3, y5+0.28, 3.0, 1.05, bd=C_REPORT_BD)
    cells += [sbom_box, stix_box, siem_box, slsa_box]

    # === 화살표 ===
    # Client → Analysis (3개 수직)
    cells.append(arrow(cli_id, stat_id, color=C_CLIENT_BD))
    cells.append(arrow(ext_id, behv_id, color=C_CLIENT_BD))
    cells.append(arrow(rest_id, llm_id, color=C_CLIENT_BD))

    # Analysis → Decision (Rule Engine)
    cells.append(arrow(stat_id, rule_id, color=C_ANALYSIS_BD))
    cells.append(arrow(behv_id, rule_id, color=C_ANALYSIS_BD))
    cells.append(arrow(llm_id, rule_id, color=C_ANALYSIS_BD))

    # Analysis (Behavioral + LLM) → Manifest Diff (보라 강조)
    cells.append(arrow(behv_id, man_id, color=C_MANIFEST))
    cells.append(arrow(llm_id, man_id, color=C_MANIFEST))

    # Knowledge ↔ Analysis (양방향)
    cells.append(arrow(stat_id, tdb_id, color=C_KNOWLEDGE_BD, double=True))
    cells.append(arrow(behv_id, emb_id, color=C_KNOWLEDGE_BD, double=True))
    cells.append(arrow(llm_id, cache_id, color=C_KNOWLEDGE_BD, double=True))

    # Decision → Reporting
    cells.append(arrow(rule_id, sbom_id, color=C_DECISION_BD))
    cells.append(arrow(rule_id, stix_id, color=C_DECISION_BD))
    cells.append(arrow(man_id, siem_id, color=C_DECISION_BD))
    cells.append(arrow(man_id, slsa_id, color=C_DECISION_BD))

    body = "\n        ".join(cells)
    return f'''<?xml version="1.0" encoding="UTF-8"?>
<mxfile host="app.diagrams.net" agent="pkgsentinel-gen-script" version="22.0.0">
  <diagram id="pkgsentinel-arch" name="pkgsentinel architecture">
    <mxGraphModel dx="1422" dy="794" grid="1" gridSize="10" guides="1" tooltips="1" connect="1" arrows="1" fold="1" page="1" pageScale="1" pageWidth="{CANVAS_W}" pageHeight="{CANVAS_H}" math="0" shadow="0">
      <root>
        <mxCell id="0"/>
        <mxCell id="1" parent="0"/>
        {body}
      </root>
    </mxGraphModel>
  </diagram>
</mxfile>
'''


def main():
    xml = build_xml()
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(xml, encoding="utf-8")
    print(f"Wrote: {OUT}  ({OUT.stat().st_size // 1024} KB)")
    print()
    print("열기:")
    print(f"  https://app.diagrams.net 에서 File → Open from device → {OUT.name}")
    print("  또는 VSCode 의 Draw.io Integration 확장 설치 후 직접 열기")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
