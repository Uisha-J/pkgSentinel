"""Capability vocabulary EXTEND — 3 vocabulary normalize layer.

매니페스트 작성자가 다음 세 어휘 중 *어느 것이든* 사용 가능:
  1. Canonical (우리 도구 내부, 15종) — filesystem-read, network 등
  2. 자체 어휘 (사람 친화)             — net.http, fs.read 등
  3. MITRE ATT&CK TTP                  — T1071, T1083 등 (NIST/CISA 외부 표준)

모두 같은 canonical 로 normalize. EXTEND 원칙:
  - REPLACE 아님 — 기존 canonical 어휘 그대로 유지
  - Backward compat — 기존 매니페스트 (canonical) 그대로 작동
  - Forward compat — 새 vocabulary 추가도 같은 패턴

근거: docs/2026-05-28-옵션A-vocabulary-extend.pdf
"""
from __future__ import annotations

from .capability_detector import CAPABILITIES, Capability

# ─────────────── 자체 어휘 → canonical ───────────────
# 사람 친화 namespace (Deno permissions / Capslock 등 차용)

SELF_TO_CANONICAL: dict[str, str] = {
    # network
    "net.http": Capability.NETWORK,
    "net.socket": Capability.NETWORK,
    "net.tcp": Capability.NETWORK,
    "net.udp": Capability.NETWORK,
    # filesystem
    "fs.read": Capability.FS_READ,
    "fs.write": Capability.FS_WRITE,
    # execution
    "shell.exec": Capability.SHELL,
    "proc.spawn": Capability.SHELL,
    "subprocess": Capability.SHELL,
    "dynamic_eval": Capability.CODE_EXEC,
    "code.eval": Capability.CODE_EXEC,
    # secrets / credentials
    "env.read": Capability.ENV_SECRETS,
    "secrets.read": Capability.CREDENTIAL_PATHS,
    "credentials.read": Capability.CREDENTIAL_PATHS,
    # database
    "db.access": Capability.DB_ACCESS,
    "db.read": Capability.DB_ACCESS,
    "db.write": Capability.DB_ACCESS,
    # memory / collection
    "data.collect": Capability.MEMORY_PERSIST,
    "memory.persistent": Capability.MEMORY_PERSIST,
    # agent communication
    "agent.communicate": Capability.AGENT_TO_AGENT,
    "agent.delegate": Capability.AGENT_TO_AGENT,
    # LLM call
    "llm.call": Capability.LLM_CALL,
    "llm.invoke": Capability.LLM_CALL,
    # MCP
    "mcp.server": Capability.MCP_SERVER,
    "mcp.client": Capability.MCP_CLIENT,
    # tool loop
    "tool.loop": Capability.TOOL_LOOP,
    "tool.dispatch": Capability.TOOL_LOOP,
    # dynamic tool loading
    "tool.load.dynamic": Capability.DYNAMIC_TOOL_LOAD,
    "plugin.load": Capability.DYNAMIC_TOOL_LOAD,
}


# ─────────────── MITRE ATT&CK TTP → canonical ───────────────
# Enterprise TTPs (외부 표준 anchor — NIST/CISA 권장)
# 출처: attack.mitre.org/techniques/enterprise/

MITRE_TO_CANONICAL: dict[str, str] = {
    # TA0011 Command & Control
    "T1071":     Capability.NETWORK,           # Application Layer Protocol
    "T1071.001": Capability.LLM_CALL,           # Web Protocols (LLM API 호출 sub)
    "T1071.004": Capability.NETWORK,            # DNS
    "T1090":     Capability.AGENT_TO_AGENT,     # Proxy
    "T1102":     Capability.NETWORK,            # Web Service
    "T1095":     Capability.NETWORK,            # Non-Application Layer Protocol

    # TA0007 Discovery
    "T1083":     Capability.FS_READ,            # File and Directory Discovery
    "T1082":     Capability.FS_READ,            # System Information Discovery
    "T1518":     Capability.FS_READ,            # Software Discovery

    # TA0040 Impact
    "T1565":     Capability.FS_WRITE,           # Data Manipulation
    "T1485":     Capability.FS_WRITE,           # Data Destruction
    "T1486":     Capability.FS_WRITE,           # Data Encrypted for Impact

    # TA0002 Execution
    "T1059":     Capability.CODE_EXEC,          # Command and Scripting Interpreter
    "T1059.001": Capability.SHELL,              # PowerShell
    "T1059.003": Capability.SHELL,              # Windows Command Shell
    "T1059.004": Capability.SHELL,              # Unix Shell
    "T1059.006": Capability.CODE_EXEC,          # Python
    "T1106":     Capability.SHELL,              # Native API
    "T1129":     Capability.DYNAMIC_TOOL_LOAD,  # Shared Modules

    # TA0006 Credential Access
    "T1552":     Capability.ENV_SECRETS,        # Unsecured Credentials
    "T1552.001": Capability.CREDENTIAL_PATHS,   # Credentials In Files
    "T1555":     Capability.CREDENTIAL_PATHS,   # Credentials from Password Stores

    # TA0009 Collection
    "T1119":     Capability.MEMORY_PERSIST,     # Automated Collection
    "T1005":     Capability.DB_ACCESS,          # Data from Local System
    "T1213":     Capability.DB_ACCESS,          # Data from Information Repositories
}


CANONICAL_SET: set[str] = set(CAPABILITIES)


# ─────────────── normalize 함수 ───────────────

def normalize(cap: str) -> str | None:
    """외부 어휘 → canonical. unknown 이면 None.

    Lookup 순서:
      1. 이미 canonical?
      2. 자체 어휘 (net.http 등)?
      3. MITRE TTP (T1071 등)?
      4. 그 외 → None (unknown)
    """
    if not cap:
        return None
    cap = cap.strip()
    if cap in CANONICAL_SET:
        return cap
    if cap in SELF_TO_CANONICAL:
        return SELF_TO_CANONICAL[cap]
    if cap in MITRE_TO_CANONICAL:
        return MITRE_TO_CANONICAL[cap]
    return None


def normalize_set(caps) -> tuple[set[str], list[str]]:
    """list/set of capabilities → (canonical set, unknown list).

    Returns:
      canonical: 정규화된 canonical 어휘 set
      unknown:   어느 vocabulary 에도 매칭 안 된 항목 (오타/신규)
    """
    canonical: set[str] = set()
    unknown: list[str] = []
    for c in caps or []:
        n = normalize(c)
        if n is None:
            unknown.append(c)
        else:
            canonical.add(n)
    return canonical, sorted(unknown)


# ─────────────── 메타데이터 ───────────────

def vocabulary_stats() -> dict:
    """각 vocabulary 의 항목 수 (문서화용)."""
    return {
        "canonical": len(CANONICAL_SET),
        "self_vocab": len(SELF_TO_CANONICAL),
        "mitre_ttp":  len(MITRE_TO_CANONICAL),
        "clusters":   len(set(SELF_TO_CANONICAL.values()) |
                          set(MITRE_TO_CANONICAL.values()) |
                          CANONICAL_SET),
    }
