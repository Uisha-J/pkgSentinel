"""
Agentic Manifest 파서.

근거: spec/AGENTIC-CAPABILITY-MANIFEST-SPEC.md (v0.1)

위치:
  - Python: pyproject.toml [tool.agentic]
  - npm:    package.json  "agentic"
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field

from .capability_detector import CAPABILITIES
from .cluster import normalize_set

# canonical capability 어휘 (15종). 선언된 capability 중 이 집합에 없는 항목은
# 오타/쓰레기로 간주 — declared_set 에서 제외하고 unknown 으로 보고한다 (Q-5).
# v2 (EXTEND): 자체 어휘 (net.http, T1071 등) 도 cluster.normalize() 로 canonical
# 변환 후 비교 (backward compat 유지 + 외부 vocabulary 지원).
_CANONICAL_CAPS: frozenset[str] = frozenset(CAPABILITIES)

# ─────────────── Schema ───────────────

@dataclass
class RuleOfTwoDecl:
    satisfies: list[str] = field(default_factory=list)   # ["A", "B"] 등
    session_isolation: bool = False


@dataclass
class DesignPatternsDecl:
    applied: list[str] = field(default_factory=list)


@dataclass
class ToolRegistryDecl:
    dynamic_tools: bool = False
    tool_signature_verification: bool = False
    trusted_tool_sources: list[str] = field(default_factory=list)


@dataclass
class AgenticManifest:
    """parsed manifest 구조. None = manifest 부재."""
    agentic: bool
    spec_version: str = "0.1"
    capabilities: list[str] = field(default_factory=list)
    opt_in_required: bool = True
    sandbox_recommended: bool = False
    rule_of_two: RuleOfTwoDecl = field(default_factory=RuleOfTwoDecl)
    design_patterns: DesignPatternsDecl = field(default_factory=DesignPatternsDecl)
    tool_registry: ToolRegistryDecl = field(default_factory=ToolRegistryDecl)

    @property
    def declared_set(self) -> set[str]:
        """canonical 어휘로 검증된 declared capability set (EXTEND v2).

        v2 변경 (Q-5 보강): 작성자가 자체 어휘 (net.http) 또는 MITRE TTP (T1071)
        로 declared 한 경우도 cluster.normalize() 로 canonical 변환 후 비교.
        backward compat — 기존 canonical 어휘 그대로 작동.
        """
        canonical, _unknown = normalize_set(self.capabilities)
        return canonical

    @property
    def unknown_capabilities(self) -> list[str]:
        """canonical / 자체 / MITRE 어느 vocabulary 에도 매칭 안 된 선언 (오타/신규)."""
        _canonical, unknown = normalize_set(self.capabilities)
        return unknown

    def to_dict(self) -> dict:
        return {
            "agentic": self.agentic,
            "spec_version": self.spec_version,
            "capabilities": self.capabilities,
            "opt_in_required": self.opt_in_required,
            "sandbox_recommended": self.sandbox_recommended,
            "rule_of_two": {
                "satisfies": self.rule_of_two.satisfies,
                "session_isolation": self.rule_of_two.session_isolation,
            },
            "design_patterns": {"applied": self.design_patterns.applied},
            "tool_registry": {
                "dynamic_tools": self.tool_registry.dynamic_tools,
                "tool_signature_verification": self.tool_registry.tool_signature_verification,
                "trusted_tool_sources": self.tool_registry.trusted_tool_sources,
            },
        }


# ─────────────── Python (pyproject.toml) ───────────────

def parse_python_pyproject(content: str) -> AgenticManifest | None:
    """pyproject.toml 텍스트 → manifest. [tool.agentic] 없으면 None."""
    try:
        try:
            import tomllib  # Python 3.11+
            data = tomllib.loads(content)
        except (ImportError, AttributeError):
            import tomli  # type: ignore
            data = tomli.loads(content)
    except Exception:
        return None

    tool = (data.get("tool") or {}).get("agentic")
    if not tool:
        return None
    return _from_dict(tool)


# ─────────────── npm (package.json) ───────────────

def parse_npm_package(content: str) -> AgenticManifest | None:
    """package.json 텍스트 → manifest. 'agentic' 키 없으면 None."""
    try:
        data = json.loads(content)
    except Exception:
        return None

    block = data.get("agentic")
    if not block:
        return None
    # camelCase → snake_case 정규화
    normalized = {
        "agentic": block.get("agentic", False),
        "spec_version": block.get("specVersion") or block.get("spec_version", "0.1"),
        "capabilities": block.get("capabilities", []),
        "opt_in_required": block.get("optInRequired", block.get("opt_in_required", True)),
        "sandbox_recommended": block.get("sandboxRecommended",
                                         block.get("sandbox_recommended", False)),
        "rule_of_two": _normalize_keys(
            block.get("ruleOfTwo") or block.get("rule_of_two") or {},
            {"sessionIsolation": "session_isolation"},
        ),
        "design_patterns": block.get("designPatterns") or block.get("design_patterns") or {},
        "tool_registry": _normalize_keys(
            block.get("toolRegistry") or block.get("tool_registry") or {},
            {
                "dynamicTools": "dynamic_tools",
                "toolSignatureVerification": "tool_signature_verification",
                "trustedToolSources": "trusted_tool_sources",
            },
        ),
    }
    return _from_dict(normalized)


def _normalize_keys(d: dict, mapping: dict[str, str]) -> dict:
    out = {}
    for k, v in d.items():
        out[mapping.get(k, k)] = v
    return out


# ─────────────── 통합 ───────────────

def parse_manifest(*, pyproject_text: str | None = None,
                   package_json_text: str | None = None,
                   ) -> AgenticManifest | None:
    """둘 중 하나만 있으면 그것 사용. 둘 다 있으면 npm 우선."""
    if package_json_text is not None:
        m = parse_npm_package(package_json_text)
        if m:
            return m
    if pyproject_text is not None:
        m = parse_python_pyproject(pyproject_text)
        if m:
            return m
    return None


# ─────────────── helpers ───────────────

def _from_dict(d: dict) -> AgenticManifest:
    rt = d.get("rule_of_two") or {}
    dp = d.get("design_patterns") or {}
    tr = d.get("tool_registry") or {}
    return AgenticManifest(
        agentic=bool(d.get("agentic", False)),
        spec_version=str(d.get("spec_version", "0.1")),
        capabilities=list(d.get("capabilities") or []),
        opt_in_required=bool(d.get("opt_in_required", True)),
        sandbox_recommended=bool(d.get("sandbox_recommended", False)),
        rule_of_two=RuleOfTwoDecl(
            satisfies=list(rt.get("satisfies") or []),
            session_isolation=bool(rt.get("session_isolation", False)),
        ),
        design_patterns=DesignPatternsDecl(
            applied=list(dp.get("applied") or []),
        ),
        tool_registry=ToolRegistryDecl(
            dynamic_tools=bool(tr.get("dynamic_tools", False)),
            tool_signature_verification=bool(
                tr.get("tool_signature_verification", False)
            ),
            trusted_tool_sources=list(tr.get("trusted_tool_sources") or []),
        ),
    )
