"""pkgsentinel server CLI 진입점.

사용:
  python -m pkgsentinel.server [--bind 0.0.0.0] [--port 8787] [--debug]

prod 에서는 gunicorn 권장:
  gunicorn -w 4 -b 0.0.0.0:8787 pkgsentinel.server:app
"""
from __future__ import annotations

import argparse
import logging
import os
import sys

from .. import _dotenv as _aislopsq_dotenv
from .app import create_app

_aislopsq_dotenv.load()


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="pkgsentinel HTTP server")
    # 기본 bind 는 loopback (127.0.0.1). 외부 노출은 명시적 opt-in 필요 —
    # 구버전 0.0.0.0 기본값 + 무인증 통과가 결합되면 누구나 분석/인텔을
    # 트리거할 수 있었음.
    p.add_argument("--bind", default=os.environ.get("PKGSENTINEL_BIND", "127.0.0.1"))
    p.add_argument("--port", type=int,
                   default=int(os.environ.get("PKGSENTINEL_PORT", "8787")))
    p.add_argument("--debug", action="store_true",
                   help="Flask debug 모드 (dev 전용)")
    p.add_argument("--log-level", default="INFO",
                   choices=["DEBUG", "INFO", "WARNING", "ERROR"])
    args = p.parse_args(argv)

    logging.basicConfig(
        level=args.log_level,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    # HMAC secret 자세 (fail-closed). secret 없고 dev opt-in 없으면 보호
    # endpoint 가 503 을 반환한다 (app._auth_posture).
    _has_secret = bool(os.environ.get("PKGSENTINEL_HMAC_SECRET", "").strip())
    _dev_no_auth = os.environ.get("PKGSENTINEL_DEV_NO_AUTH", "").strip().lower() in (
        "1", "true", "yes", "on",
    )
    if not _has_secret and _dev_no_auth:
        print(
            "WARNING: PKGSENTINEL_DEV_NO_AUTH set — HMAC 검증 비활성 (dev only, insecure)",
            file=sys.stderr,
        )
    elif not _has_secret:
        print(
            "WARNING: PKGSENTINEL_HMAC_SECRET not set — 보호 endpoint 는 503 반환 "
            "(fail-closed). dev 라면 PKGSENTINEL_DEV_NO_AUTH=1 설정.",
            file=sys.stderr,
        )
    if args.bind == "0.0.0.0" and not _has_secret:
        print(
            "WARNING: binding 0.0.0.0 without HMAC secret — 외부 노출 위험.",
            file=sys.stderr,
        )

    app = create_app()
    print(
        f"pkgsentinel server listening on http://{args.bind}:{args.port}",
        file=sys.stderr,
    )
    app.run(host=args.bind, port=args.port, debug=args.debug, threaded=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
