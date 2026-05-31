"""cluster.normalize EXTEND 단위 테스트.

3 vocabulary 모두 같은 canonical 로 normalize 되는지 검증.
backward compat 확인 (기존 canonical 어휘 그대로 작동).
"""
from __future__ import annotations

from pkgsentinel.agentic.cluster import normalize, normalize_set
from pkgsentinel.agentic.manifest import parse_python_pyproject


# ─────────────── normalize() ───────────────

def test_canonical_passes_through():
    """canonical 어휘는 그대로 반환 (backward compat)."""
    assert normalize("filesystem-read") == "filesystem-read"
    assert normalize("network") == "network"
    assert normalize("shell") == "shell"
    assert normalize("env-secrets") == "env-secrets"


def test_self_vocab_maps_to_canonical():
    """자체 어휘 (net.http 등) → canonical."""
    assert normalize("net.http") == "network"
    assert normalize("net.socket") == "network"
    assert normalize("fs.read") == "filesystem-read"
    assert normalize("fs.write") == "filesystem-write"
    assert normalize("shell.exec") == "shell"
    assert normalize("env.read") == "env-secrets"
    assert normalize("secrets.read") == "credential-paths"


def test_mitre_ttp_maps_to_canonical():
    """MITRE ATT&CK TTP → canonical."""
    assert normalize("T1071") == "network"
    assert normalize("T1083") == "filesystem-read"
    assert normalize("T1059") == "code-exec"
    assert normalize("T1552") == "env-secrets"
    assert normalize("T1552.001") == "credential-paths"


def test_unknown_returns_none():
    """어느 vocabulary 에도 매칭 안 되면 None."""
    assert normalize("net.weird") is None
    assert normalize("T9999") is None
    assert normalize("rubbish") is None
    assert normalize("") is None


def test_three_vocabularies_yield_same_canonical():
    """세 vocabulary 가 같은 의미면 같은 canonical."""
    canonical = normalize("network")
    self_v = normalize("net.http")
    mitre_v = normalize("T1071")
    assert canonical == self_v == mitre_v == "network"


# ─────────────── normalize_set() ───────────────

def test_normalize_set_mixed():
    """혼합 vocabulary list → (canonical set, unknown)."""
    caps = ["net.http", "T1083", "shell", "weird-cap"]
    canonical, unknown = normalize_set(caps)
    assert canonical == {"network", "filesystem-read", "shell"}
    assert unknown == ["weird-cap"]


def test_normalize_set_empty():
    canonical, unknown = normalize_set([])
    assert canonical == set()
    assert unknown == []


def test_normalize_set_dedupes():
    """다른 vocabulary 가 같은 canonical 매핑 → set 중복 제거."""
    caps = ["network", "net.http", "T1071"]
    canonical, _ = normalize_set(caps)
    assert canonical == {"network"}


# ─────────────── manifest 통합 ───────────────

def _toml(caps_text: str) -> str:
    return f"""
[tool.agentic]
agentic = true
capabilities = {caps_text}
"""


def test_manifest_declared_set_canonical():
    """기존 canonical 어휘 — backward compat."""
    m = parse_python_pyproject(_toml(
        '["network", "filesystem-read", "shell"]'
    ))
    assert m is not None
    assert m.declared_set == {"network", "filesystem-read", "shell"}
    assert m.unknown_capabilities == []


def test_manifest_declared_set_self_vocab():
    """자체 어휘 → canonical normalize."""
    m = parse_python_pyproject(_toml(
        '["net.http", "fs.read", "shell.exec"]'
    ))
    assert m is not None
    assert m.declared_set == {"network", "filesystem-read", "shell"}
    assert m.unknown_capabilities == []


def test_manifest_declared_set_mitre():
    """MITRE TTP → canonical normalize."""
    m = parse_python_pyproject(_toml(
        '["T1071", "T1083", "T1059"]'
    ))
    assert m is not None
    assert m.declared_set == {"network", "filesystem-read", "code-exec"}
    assert m.unknown_capabilities == []


def test_manifest_declared_set_mixed():
    """혼합 (자체 + MITRE + canonical) → canonical set."""
    m = parse_python_pyproject(_toml(
        '["net.http", "T1083", "shell", "rubbish"]'
    ))
    assert m is not None
    assert m.declared_set == {"network", "filesystem-read", "shell"}
    assert m.unknown_capabilities == ["rubbish"]
