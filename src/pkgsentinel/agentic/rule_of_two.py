"""
Meta Agents Rule of Two — Lethal Trifecta 검출 + HITL 시그니처.

근거: papers/05-meta-agents-rule-of-two.md, spec/RULES.md (R2-1)

규칙: A(외부 입력) + B(민감 데이터) + C(상태 변경/외부 통신) 동시 보유 시
       prompt injection 최악 시나리오 가능. HITL 또는 session_isolation 으로만 완화.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

from .capability_detector import map_to_abc


@dataclass
class LethalTrifectaCheck:
    detected_caps: set[str]
    abc_present: set[str]
    has_trifecta: bool
    has_human_in_the_loop: bool
    declared_satisfies: list[str]
    declared_session_isolation: bool
    # 선언이 코드 시그니처로 뒷받침되는지 (스펙 §5). 기본 False.
    session_isolation_verified: bool = False

    @property
    def session_isolation_effective(self) -> bool:
        # 선언만으로는 면책 불가 — 실제 컨텍스트 리셋 시그니처가 있을 때만 인정.
        return self.declared_session_isolation and self.session_isolation_verified

    @property
    def is_violation(self) -> bool:
        return self.has_trifecta and not self.has_human_in_the_loop \
               and not self.session_isolation_effective

    def to_dict(self) -> dict:
        return {
            "abc_present": sorted(self.abc_present),
            "has_trifecta": self.has_trifecta,
            "has_human_in_the_loop": self.has_human_in_the_loop,
            "declared_satisfies": self.declared_satisfies,
            "declared_session_isolation": self.declared_session_isolation,
            "session_isolation_verified": self.session_isolation_verified,
            "session_isolation_effective": self.session_isolation_effective,
            "is_violation": self.is_violation,
        }


def has_lethal_trifecta(
    detected: set[str],
    *,
    has_hitl: bool = False,
    declared_satisfies: list[str] | None = None,
    declared_session_isolation: bool = False,
    session_isolation_verified: bool = False,
) -> LethalTrifectaCheck:
    abc = map_to_abc(detected)
    return LethalTrifectaCheck(
        detected_caps=set(detected),
        abc_present=abc,
        has_trifecta=len(abc) == 3,
        has_human_in_the_loop=has_hitl,
        declared_satisfies=list(declared_satisfies or []),
        declared_session_isolation=declared_session_isolation,
        session_isolation_verified=session_isolation_verified,
    )


# ─────────────── HITL 검출 ───────────────

_HITL_PYTHON_PATTERNS = [
    re.compile(r"\binput\s*\(\s*[\"'][^\"']*\?[^\"']*[\"']\s*\)"),
    re.compile(r"\bconfirm\s*\("),
    re.compile(r"\bapproval_required\s*=\s*True"),
    re.compile(r"\bhuman_in_the_loop\b"),
    re.compile(r"\bHumanInTheLoop\b"),
    re.compile(r"\brequest_approval\b"),
    re.compile(r"@requires_approval\b"),
    re.compile(r"\bask_user_to_continue\b"),
]

_HITL_JS_PATTERNS = [
    re.compile(r"\breadlineSync\b"),
    re.compile(r"\binquirer\b"),
    re.compile(r"\bprompts\s*\("),
    re.compile(r"\brequireApproval\b"),
    re.compile(r"\bhumanInTheLoop\b"),
    re.compile(r"\bHumanInTheLoop\b"),
]


def detect_human_in_the_loop(
    sources: dict[str, str],
    *,
    language: str = "python",
) -> bool:
    """sources 안에 HITL 메커니즘 시그니처가 있는지."""
    pats = (_HITL_PYTHON_PATTERNS if language.startswith("py")
            else _HITL_JS_PATTERNS)
    for src in sources.values():
        if any(p.search(src) for p in pats):
            return True
    return False


# ─────────────── session_isolation 구현 검증 (스펙 §5) ───────────────
# 선언된 session_isolation 을 뒷받침하는 코드 시그니처. 매 턴/세션마다
# 컨텍스트(메시지 히스토리)를 비우거나 새 세션을 생성하는 흔적이 있어야 인정.
# 선언만으로는 면책 불가 — 검증 없는 선언은 심각도를 낮추지 못한다.
_SESSION_RESET_PY = [
    re.compile(r"\bmessages\s*=\s*\[\s*\]"),                 # 히스토리 초기화
    re.compile(r"\b(?:reset|clear)_(?:context|history|memory|session)\b", re.I),
    re.compile(r"\bnew_session\b|\bfresh_context\b", re.I),
    re.compile(r"\bConversation\w*Memory\b[\s\S]{0,40}\.clear\s*\(", re.I),
    re.compile(r"\bsession_isolation\s*=\s*True\b"),          # 프레임워크 플래그 실제 설정
]
_SESSION_RESET_JS = [
    re.compile(r"\bmessages\s*=\s*\[\s*\]"),
    re.compile(r"\b(?:reset|clear)(?:Context|History|Memory|Session)\b"),
    re.compile(r"\bnewSession\b|\bfreshContext\b"),
    re.compile(r"\bsessionIsolation\s*:\s*true\b"),
]


def verify_session_isolation(
    sources: dict[str, str],
    *,
    language: str = "python",
) -> bool:
    """선언된 session_isolation 이 코드로 뒷받침되는지 확인.

    매 상호작용마다 컨텍스트를 리셋/격리하는 시그니처가 하나라도 있으면 True.
    없으면 선언은 'UNVERIFIED' 로 간주되어 면책 효과를 받지 못한다.
    """
    pats = _SESSION_RESET_PY if language.startswith("py") else _SESSION_RESET_JS
    for src in sources.values():
        if any(p.search(src) for p in pats):
            return True
    return False
