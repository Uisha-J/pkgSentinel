"""pkgsentinel C4 Container 다이어그램 → draw.io(.drawio) XML 내보내기.

matplotlib 버전과 동일 레이아웃. 노드 ID로 엣지를 연결해 draw.io 가 자동 라우팅.
산출: docs/pkgsentinel_c4_container.drawio  (draw.io / diagrams.net 에서 열어 편집)
"""
from pathlib import Path
from xml.sax.saxutils import escape

SCALE = 80
H = 9.2  # matplotlib y 최대 (Y 뒤집기용)


def X(mx): return round(mx * SCALE)
def Y(my, h): return round((H - my - h) * SCALE)   # 상단-왼쪽 (drawio Y 아래로 증가)
def W(w): return round(w * SCALE)
def Hh(h): return round(h * SCALE)


def lbl(s):
    return escape(s).replace("\n", "&#10;")


# (id, mx, my, w, h, label, fill, font, extra)
ACTOR = "rounded=1;whiteSpace=wrap;html=1;fillColor=#1B2A4A;strokeColor=#14223B;fontColor=#FFFFFF;fontSize=11;"
def cont(fill, stroke):
    return f"rounded=1;whiteSpace=wrap;html=1;fillColor={fill};strokeColor={stroke};fontColor=#FFFFFF;fontSize=11;"
EXT = "rounded=1;whiteSpace=wrap;html=1;fillColor=#8895A7;strokeColor=#5B6677;fontColor=#FFFFFF;fontSize=11;"

NODES = [
    # 액터
    ("dev",   0.3, 6.7, 1.1, 1.1, "개발자\n패키지 검사", ACTOR),
    ("cicd",  0.3, 5.2, 1.1, 1.1, "CI/CD\n파이프라인 게이트", ACTOR),
    ("analyst", 0.3, 0.55, 1.1, 1.1, "보안 분석가\nSIEM 수신", ACTOR),
    # 클라이언트
    ("cli",  2.6, 6.7, 2.35, 1.0, "CLI\n[Python]\npkgsentinel check", cont("#1168BD", "#0D4C8B")),
    ("api",  5.18, 6.7, 2.35, 1.0, "REST API\n[FastAPI · HTTP]\n/analyze /runtime-alert", cont("#1168BD", "#0D4C8B")),
    ("ext",  7.76, 6.7, 2.45, 1.0, "IDE / Browser Ext\n[VSCode · Chrome MV3]\n실시간 인라인 경고", cont("#1168BD", "#0D4C8B")),
    # 분석 엔진
    ("engine", 3.5, 4.65, 5.6, 1.45, "Analysis Engine\n[7계층 / 21단계 파이프라인]\n정적(AST·taint) · 행위(MITRE TTP·47-indicator) · LLM 검증", cont("#1C7293", "#125064")),
    # 지식
    ("tidb", 2.6, 3.0, 2.35, 1.15, "Threat Intel DB\n[OSV · OSSF]\nknown-malicious", cont("#2C5F5A", "#1E4541")),
    ("emb",  5.18, 3.0, 2.35, 1.15, "TTP Embeddings\n[MiniLM · 568 TTP]\ncosine 매칭", cont("#2C5F5A", "#1E4541")),
    ("cache", 7.76, 3.0, 2.45, 1.15, "Encrypted Cache\n[SQLCipher AES-256]\nthreat_db.sqlcipher", cont("#2C5F5A", "#1E4541")),
    # 판정
    ("rule", 3.1, 1.66, 3.3, 0.98, "Rule Engine\n[verdict_rules]\n3-AND · threshold", cont("#7A5C1E", "#564214")),
    ("manifest", 6.7, 1.66, 3.5, 0.98, "Agentic Manifest Diff  ★\ndeclared vs detected\n미선언 권한 경고", cont("#7A5C1E", "#564214")),
    # 출력
    ("out", 2.6, 0.56, 7.6, 0.92, "Output Adapters  [표준 출력 어댑터]\nSBOM/VEX · STIX 2.1/TAXII · SIEM Webhook(HMAC) · SLSA", cont("#5B6677", "#3A4D6B")),
    # 외부 시스템
    ("pypi", 11.7, 6.7, 3.0, 1.0, "PyPI / npm Registry\n[공개 레지스트리]\n패키지 아카이브", EXT),
    ("osv",  11.7, 5.25, 3.0, 1.0, "OSV / OSSF Feeds\n[Google · OpenSSF]\n악성·취약 인텔", EXT),
    ("claude", 11.7, 3.8, 3.0, 1.0, "Anthropic Claude API\n[LLM]\n3-agent 검증", EXT),
    ("mitre", 11.7, 2.35, 3.0, 1.0, "MITRE ATT&CK CTI\n[STIX 번들]\nTTP 코퍼스", EXT),
]

# (source, target, label, dashed)
EDGES = [
    ("dev", "cli", "check &lt;pkg&gt;", False),
    ("cicd", "api", "POST /analyze [HTTPS]", False),
    ("out", "analyst", "HMAC 경보", False),
    ("cli", "engine", "", False),
    ("api", "engine", "요청", False),
    ("ext", "engine", "", False),
    ("engine", "pypi", "아카이브 fetch [HTTPS·스트림]", False),
    ("engine", "osv", "known-malicious 조회", False),
    ("engine", "claude", "3-agent review [HTTPS/JSON]", False),
    ("mitre", "emb", "TTP 코퍼스 (build-time)", True),
    ("engine", "tidb", "", False),
    ("engine", "emb", "read / write", False),
    ("engine", "cache", "", False),
    ("engine", "rule", "evidence·indicators", False),
    ("engine", "manifest", "", False),
    ("rule", "out", "verdict", False),
    ("manifest", "out", "", False),
]

EDGE_STYLE = ("edgeStyle=orthogonalEdgeStyle;rounded=1;html=1;endArrow=block;"
              "fontSize=10;fontColor=#3A4D6B;strokeColor=#5B6677;")
EDGE_DASH = EDGE_STYLE + "dashed=1;strokeColor=#8895A7;"

cells = []
# 경계 (맨 처음 = 뒤)
cells.append(
    f'<mxCell id="boundary" value="{lbl("pkgsentinel  [Software System]")}" '
    f'style="rounded=1;dashed=1;fillColor=#F2F7FD;strokeColor=#1168BD;verticalAlign=top;'
    f'align=left;fontColor=#1168BD;fontStyle=1;fontSize=12;spacingTop=6;spacingLeft=8;html=1;" '
    f'vertex="1" parent="1"><mxGeometry x="{X(2.35)}" y="{Y(0.45,7.55)}" '
    f'width="{W(8.05)}" height="{Hh(7.55)}" as="geometry"/></mxCell>')

for nid, mx, my, w, h, label, style in NODES:
    cells.append(
        f'<mxCell id="{nid}" value="{lbl(label)}" style="{style}" vertex="1" parent="1">'
        f'<mxGeometry x="{X(mx)}" y="{Y(my,h)}" width="{W(w)}" height="{Hh(h)}" as="geometry"/></mxCell>')

for i, (src, tgt, label, dash) in enumerate(EDGES):
    st = EDGE_DASH if dash else EDGE_STYLE
    cells.append(
        f'<mxCell id="e{i}" value="{lbl(label)}" style="{st}" edge="1" parent="1" '
        f'source="{src}" target="{tgt}"><mxGeometry relative="1" as="geometry"/></mxCell>')

xml = f'''<mxfile host="app.diagrams.net" type="device">
  <diagram name="pkgsentinel C4 Container" id="pkgsentinel-c4">
    <mxGraphModel dx="1400" dy="900" grid="1" gridSize="10" guides="1" tooltips="1"
        connect="1" arrows="1" fold="1" page="1" pageScale="1" pageWidth="1300" pageHeight="800"
        math="0" shadow="0">
      <root>
        <mxCell id="0"/>
        <mxCell id="1" parent="0"/>
        {"".join(chr(10) + "        " + c for c in cells)}
        <mxCell id="title" value="pkgsentinel — 시스템 구조 (C4 Container)" style="text;html=1;align=center;fontSize=18;fontStyle=1;fontColor=#1B2A4A;" vertex="1" parent="1"><mxGeometry x="{X(4.0)}" y="10" width="{W(7)}" height="34" as="geometry"/></mxCell>
      </root>
    </mxGraphModel>
  </diagram>
</mxfile>'''

out = Path(__file__).resolve().parent.parent / "docs" / "pkgsentinel_c4_container.drawio"
out.write_text(xml, encoding="utf-8")
print("saved:", out)
print("nodes:", len(NODES), "edges:", len(EDGES))
