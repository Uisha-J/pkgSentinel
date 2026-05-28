"""환경변수 조회 — PKGSENTINEL_* 우선, 구 AISLOP_* fallback.

프로젝트 리브랜딩(AISLOPSQ → pkgsentinel)으로 환경변수 접두사가
`AISLOP_` → `PKGSENTINEL_` 로 바뀌었다. 기존 배포(.env, systemd
EnvironmentFile, CI secret 등)가 깨지지 않도록, 읽기 시점에 새 이름을
먼저 보고 없으면 구 이름으로 fallback 한다.

읽기 지점에서 fallback 하므로 `_dotenv.load()` 호출 타이밍과 무관하게
동작한다. 새 코드/문서는 항상 PKGSENTINEL_* 정규 이름을 사용한다.
"""
from __future__ import annotations

import os

PREFIX = "PKGSENTINEL_"
LEGACY_PREFIX = "AISLOP_"


def legacy_name(name: str) -> str | None:
    """PKGSENTINEL_X → AISLOP_X. 접두사가 아니면 None."""
    if name.startswith(PREFIX):
        return LEGACY_PREFIX + name[len(PREFIX):]
    return None


def getenv(name: str, default: str | None = None) -> str | None:
    """PKGSENTINEL_* 우선 조회, 없으면 구 AISLOP_* 로 fallback.

    `name` 은 정규(신규) 이름을 넘긴다 (예: "PKGSENTINEL_DB_KEY").
    둘 다 없으면 `default`.
    """
    v = os.environ.get(name)
    if v is not None:
        return v
    legacy = legacy_name(name)
    if legacy is not None:
        v = os.environ.get(legacy)
        if v is not None:
            return v
    return default
