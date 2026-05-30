"""markdown-pinpoint — 스킬 지시문(SKILL.md/마크다운) 내 LLM-지향 악성 콘텐츠 탐지.

배경: ai-skills/MCP 공격은 코드가 아니라 'AI 에이전트에게 주는 자연어 지시'(SKILL.md,
      tool description)에 있어 기존 SAST(코드 취약점 스캐너)가 구조적으로 못 잡는다.
      → pkgsentinel 행위 분석(Python/JS)을 보완해, 마크다운/지시문 표면을 커버.

선행/출처: 프롬프트 인젝션 패턴은 Sentry skill-scanner(getsentry/skills, scan_skill.py)
           의 PROMPT_INJECTION_PATTERNS 를 적응. 코드펜스 exfil 은 indicator_matcher 의
           _NPM_SCRIPT_DANGEROUS 와 동일 계열. MCP tool-poisoning 개념(Invariant Labs).

탐지 범주:
  PI  프롬프트 인젝션 / 지시문 탈취 / jailbreak / system prompt 추출
  FENCE  마크다운 코드펜스(```bash/js/python) 안의 exfil/원격실행
  EXFIL  자격증명·민감파일 접근 + 외부 전송을 지시하는 문장
  HIDE  은닉(HTML 주석 내 지시, zero-width 유니코드, base64 디코딩 시 인젝션)
"""
from __future__ import annotations

import base64
import re
from dataclasses import dataclass, field

# ── 프롬프트 인젝션 (Sentry skill-scanner 적응) ──────────────────────────
PROMPT_INJECTION = [
    (re.compile(r"(?i)ignore\s+(all\s+)?previous\s+instructions"), "지시문 무시(ignore previous)", "critical"),
    (re.compile(r"(?i)disregard\s+(all\s+)?(previous|prior|above)\s+(instructions|rules|guidelines)"), "지시문 무시(disregard)", "critical"),
    (re.compile(r"(?i)forget\s+(all\s+)?(previous|prior|your)\s+(instructions|rules|training)"), "지시문 무시(forget)", "critical"),
    (re.compile(r"(?i)you\s+are\s+now\s+(a|an|in)\s+"), "역할 재지정(you are now)", "high"),
    (re.compile(r"(?i)act\s+as\s+(a|an)\s+unrestricted"), "unrestricted 모드", "critical"),
    (re.compile(r"(?i)enter\s+(developer|debug|admin|god)\s+mode"), "jailbreak(dev/debug mode)", "critical"),
    (re.compile(r"(?i)\bDAN\s+(mode|prompt|jailbreak)|do\s+anything\s+now"), "jailbreak(DAN)", "critical"),
    (re.compile(r"(?i)bypass\s+(safety|security|content|filter|restriction)"), "안전장치 우회", "critical"),
    (re.compile(r"(?i)override\s+(system|safety|security)\s+(prompt|message|instruction)"), "system prompt override", "critical"),
    (re.compile(r"(?i)new\s+system\s+(prompt|instruction|message)\s*:"), "신규 system prompt 주입", "critical"),
    (re.compile(r"(?i)from\s+now\s+on,?\s+(you|ignore|forget|disregard)"), "시간적 지시 override", "high"),
    (re.compile(r"(?i)(output|reveal|repeat|print)\s+(your|the)\s+(system|initial|original)\s+(prompt|instructions)"), "system prompt 추출", "high"),
    (re.compile(r"(?i)do\s+not\s+(tell|inform|mention\s+to|alert)\s+the\s+user"), "사용자 은폐 지시", "high"),
    # '은밀 실행' 은 명령형 동사와 결합될 때만 (bare 'silently' 오탐 방지)
    (re.compile(r"(?i)(silently|secretly|covertly|without\s+(the\s+user|them)\s+knowing)\s+"
                r"(run|execute|send|post|upload|exfiltrate|read|collect|copy|curl|fetch|download)"),
     "은밀 실행/전송 지시", "high"),
]

# ── 코드펜스 안 위험 (install-hook 계열 + 추가) ──────────────────────────
FENCE_RE = re.compile(r"```(?:bash|sh|shell|js|javascript|python|py|node)?\s*\n(.*?)```", re.DOTALL | re.IGNORECASE)
# 고신뢰 exfil/원격실행만 (bare github/oauth URL 등 정상 문서 제외)
FENCE_DANGEROUS = re.compile(
    r"(?:\bcurl\b[^\n]*(?:--data|--data-urlencode|-d\s|-X\s*POST|-T\s)|"     # curl 데이터 전송(exfil)
    r"(?:curl|wget)\b[^\n|]*\|\s*(?:bash|sh|node|python)\b|"                  # 다운로드→셸 실행
    r"nc\s+-[le]|/dev/tcp/|"                                                  # reverse shell
    r"oast(?:ify)?\.|burpcollaborator|interactsh|\bpinggy\b|\bngrok\b|webhook\.site|requestbin|"  # collaborator
    r"eval\s*\(\s*(?:atob|base64|Buffer\.from|unescape)|atob\s*\(|base64\s+(?:-d|--decode)|"  # decode-exec
    r"/etc/(?:shadow|passwd)|\bid_rsa\b|\.aws/credentials|\.ssh/id_|"        # 민감 파일
    r"process\.env\[?['\"]?[A-Z_]*(?:KEY|TOKEN|SECRET|PASSWORD)|"            # 시크릿 env 접근
    r"child_process[^\n]*(?:exec|spawn)[^\n]*(?:http|curl|\$\{|atob))",      # child_process 원격실행
    re.IGNORECASE,
)

# ── 자격증명 exfil 지시 (민감대상 + 전송동사) ────────────────────────────
# 고신뢰 민감 대상만 (generic token/secret/password 제외 — 정상 문서 도배)
SENSITIVE = re.compile(r"(?i)(\.aws/credentials|\.npmrc|\.ssh/id|/etc/(?:shadow|passwd)|id_rsa|"
                       r"private\s*key|\.env\b|seed\s*phrase|mnemonic|wallet\.dat|keychain)")
EXFIL_VERB = re.compile(r"(?i)(send|post|upload|exfiltrate|transmit|leak|forward)\s+.{0,40}"
                        r"(to\s+)?(https?://|webhook|attacker|c2|remote\s+server|external\s+server)")

# ── 은닉 ─────────────────────────────────────────────────────────────────
HTML_COMMENT = re.compile(r"<!--(.*?)-->", re.DOTALL)
ZERO_WIDTH = re.compile(r"[​‌‍⁠﻿­]")
B64_BLOB = re.compile(r"[A-Za-z0-9+/]{24,}={0,2}")


@dataclass
class MdHit:
    category: str
    severity: str
    file: str
    line: int
    desc: str
    evidence: str = ""


@dataclass
class MdReport:
    hits: list[MdHit] = field(default_factory=list)

    @property
    def max_severity(self) -> str:
        order = {"critical": 3, "high": 2, "medium": 1}
        return max((h.severity for h in self.hits), key=lambda s: order.get(s, 0), default="none")

    @property
    def is_malicious(self) -> bool:
        return any(h.severity in ("critical", "high") for h in self.hits)


def _lineno(text: str, idx: int) -> int:
    return text.count("\n", 0, idx) + 1


def scan_text(text: str, path: str = "") -> list[MdHit]:
    hits: list[MdHit] = []
    # 1) 프롬프트 인젝션 (원문)
    for rx, desc, sev in PROMPT_INJECTION:
        for m in rx.finditer(text):
            hits.append(MdHit("PI", sev, path, _lineno(text, m.start()), desc, m.group(0)[:120]))
    # 2) 코드펜스 안 위험
    for m in FENCE_RE.finditer(text):
        body = m.group(1)
        dm = FENCE_DANGEROUS.search(body)
        if dm:
            hits.append(MdHit("FENCE", "critical", path, _lineno(text, m.start()),
                              "마크다운 코드펜스 내 exfil/원격실행", dm.group(0)[:120]))
    # 3) 자격증명 exfil 지시 (민감대상+전송동사가 같은 ~200자 윈도)
    for sm in SENSITIVE.finditer(text):
        window = text[max(0, sm.start() - 100): sm.end() + 100]
        if EXFIL_VERB.search(window):
            hits.append(MdHit("EXFIL", "critical", path, _lineno(text, sm.start()),
                              "자격증명/민감파일 외부 전송 지시", sm.group(0)[:80]))
            break
    # 4) 은닉 — HTML 주석 안 인젝션
    for cm in HTML_COMMENT.finditer(text):
        inner = cm.group(1)
        for rx, desc, sev in PROMPT_INJECTION:
            if rx.search(inner):
                hits.append(MdHit("HIDE", "critical", path, _lineno(text, cm.start()),
                                  f"HTML 주석 은닉 인젝션: {desc}", inner.strip()[:100]))
                break
    # 5) 은닉 — zero-width 가 텍스트를 쪼개 injection 키워드를 숨긴 경우만
    #    (charset/문자처리 라이브러리는 정상적으로 zero-width 포함 → standalone 은 무시)
    if ZERO_WIDTH.search(text):
        stripped = ZERO_WIDTH.sub("", text)
        for rx, desc, _sev in PROMPT_INJECTION:
            if rx.search(stripped) and not rx.search(text):
                m = ZERO_WIDTH.search(text)
                hits.append(MdHit("HIDE", "critical", path, _lineno(text, m.start()),
                                  f"zero-width 로 분리 은닉된 인젝션: {desc}", ""))
                break
    # 6) 은닉 — base64 디코딩 시 인젝션
    for bm in B64_BLOB.finditer(text):
        blob = bm.group(0)
        try:
            dec = base64.b64decode(blob + "=" * (-len(blob) % 4), validate=False).decode("utf-8", "ignore")
        except Exception:
            continue
        if any(rx.search(dec) for rx, _, _ in PROMPT_INJECTION) or FENCE_DANGEROUS.search(dec):
            hits.append(MdHit("HIDE", "critical", path, _lineno(text, bm.start()),
                              "base64 디코딩 시 인젝션/exfil", dec[:80]))
            break
    return hits


# 스킬 지시문으로 취급할 파일 (마크다운 + 무확장 SKILL/INSTRUCTIONS 등)
_SKILL_FILE = re.compile(r"(?i)\.(md|markdown|mdx|txt)$|(^|/)(SKILL|README|INSTRUCTIONS|TOOL|AGENTS?|CLAUDE)$")


def is_skill_doc(path: str) -> bool:
    base = path.rsplit("/", 1)[-1]
    return bool(re.search(r"(?i)\.(md|markdown|mdx|txt)$", base)) or \
        base.upper() in ("SKILL", "README", "INSTRUCTIONS", "TOOL", "AGENTS", "AGENT", "CLAUDE")


def scan_files(files: dict[str, str]) -> MdReport:
    """files: {path: content}. 스킬 문서만 골라 스캔."""
    rep = MdReport()
    for path, content in files.items():
        if not is_skill_doc(path):
            continue
        rep.hits.extend(scan_text(content, path))
    return rep
