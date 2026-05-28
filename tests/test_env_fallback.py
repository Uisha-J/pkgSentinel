"""_env.getenv 의 PKGSENTINEL_* 우선 + 구 AISLOP_* fallback 동작 회귀 테스트.

리브랜딩(AISLOPSQ → pkgsentinel) 시 환경변수 접두사를 PKGSENTINEL_ 로
바꾸면서, 기존 배포가 깨지지 않도록 구 AISLOP_* 를 fallback 으로 유지한다.
이 동작이 미래에 silently 깨지지 않도록 명시적으로 못 박는다.
"""
from __future__ import annotations

from pkgsentinel._env import getenv, legacy_name


def test_new_name_only(monkeypatch):
    monkeypatch.delenv("AISLOP_DB_KEY", raising=False)
    monkeypatch.setenv("PKGSENTINEL_DB_KEY", "new")
    assert getenv("PKGSENTINEL_DB_KEY") == "new"


def test_legacy_fallback(monkeypatch):
    monkeypatch.delenv("PKGSENTINEL_DB_KEY", raising=False)
    monkeypatch.setenv("AISLOP_DB_KEY", "legacy")
    assert getenv("PKGSENTINEL_DB_KEY") == "legacy"


def test_new_name_wins_over_legacy(monkeypatch):
    monkeypatch.setenv("AISLOP_DB_KEY", "legacy")
    monkeypatch.setenv("PKGSENTINEL_DB_KEY", "new")
    assert getenv("PKGSENTINEL_DB_KEY") == "new"


def test_neither_returns_default(monkeypatch):
    monkeypatch.delenv("PKGSENTINEL_DB_KEY", raising=False)
    monkeypatch.delenv("AISLOP_DB_KEY", raising=False)
    assert getenv("PKGSENTINEL_DB_KEY") is None
    assert getenv("PKGSENTINEL_DB_KEY", "def") == "def"


def test_non_prefixed_no_fallback(monkeypatch):
    # 접두사가 아니면 fallback 대상이 아님 (표준 변수 보호).
    monkeypatch.setenv("ANTHROPIC_API_KEY", "k")
    assert getenv("ANTHROPIC_API_KEY") == "k"
    assert legacy_name("ANTHROPIC_API_KEY") is None
    assert legacy_name("PKGSENTINEL_DB_KEY") == "AISLOP_DB_KEY"


def test_master_key_resolves_via_fallback(monkeypatch):
    """master_key.from_env 가 fallback 을 실제로 타는지 end-to-end 확인."""
    from pkgsentinel.db import master_key
    monkeypatch.delenv("PKGSENTINEL_DB_KEY", raising=False)
    monkeypatch.setenv("AISLOP_DB_KEY", "  legacy-pass  ")
    assert master_key.from_env() == "legacy-pass"  # strip 도 확인
