# 2026-05-27 — 이름 변경 마이그레이션 플랜 (준비)

## 결정된 새 이름
- **매니페스트 표준**: `AISLOPSQ` → **"Agentic Capability Manifest"** (약어 ACM은
  Association for Computing Machinery 충돌 → 풀네임 표기, 코드 식별자는 `agentic`)
- **탐지 도구/브랜드**: 이미 `pkgsentinel` 로 개명됨. 그런데 코드 곳곳에
  **`ai-slopsquatting-detector` 잔재**가 남아있음(stale) → `pkgsentinel` 로 정리.

> ⚠️ 즉 이건 **두 개의 얽힌 rename** 이다:
> (1) 매니페스트 표준명, (2) 미완료된 도구 브랜드 정리. 한 번에 처리.

## ⛔ 맹목적 find-replace 금지 — `aislopsq` 토큰이 7개 역할

| # | 역할 | 예시 | 위험 | 처리 |
|---|---|---|---|---|
| 1 | **매니페스트 키** | `[tool.aislopsq]`, `"aislopsq"` (package.json) | 채택 패키지 파싱 깨짐 (현 채택≈0) | **읽기는 신구 둘 다, 쓰기는 신규.** 구 키 alias 보존 |
| 2 | **영속 리포트 필드** | `package_meta["aislopsq"]` | 캐시/다운스트림 파서 깨짐 | 신규 키로 쓰되 구 키 alias 유지 |
| 3 | **HTTP 헤더 (wire)** | `X-AISLOPSQ-Signature/Timestamp/Tool/Event` | 배포된 client↔server 쌍 깨짐 | **수신 시 신구 둘 다 허용**, 송신은 신규 |
| 4 | **툴 식별 문자열** | `ai-slopsquatting-detector`, `ai-slopsquatting/2.0` (STIX/VEX/Falco vendor) | 외부 소비자 식별 변화 | `pkgsentinel` 로 변경 (어차피 stale) |
| 5 | **OS 키링 서비스명** | `KEYRING_SERVICE="ai-slopsquatting-detector"` (master_key.py) | **기존 저장 키 조회 불가** | ⚠️ 변경 시 마이그레이션 필요 — 또는 유지 |
| 6 | **Evidence/TTP ID (영속)** | `ttp_id="AISLOPSQ-CLS"`, `AISLOPSQ-{rule}`, `llm_model="aislopsq-classifier"`, `rule_kind="aislopsq_r"` | 과거 리포트/DB 비교성 | 변경 (로컬 DB 재생성 가능) — 비교성만 주의 |
| 7 | **내부 심볼/주석/문서** | `_aislopsq_dotenv`, `generate_aislopsq_r_extension`, prose | 없음 | 자유 변경 |

## 매핑 테이블 (확정안)

| 구 토큰 | 신 토큰 | 비고 |
|---|---|---|
| `[tool.aislopsq]` / `"aislopsq"` | `[tool.agentic]` / `"agentic"` | 구 키 read-alias |
| `package_meta["aislopsq"]` | `package_meta["agentic_manifest"]` | 구 키 alias |
| `X-AISLOPSQ-*` | `X-PkgSentinel-*` | 수신 신구 허용 |
| `ai-slopsquatting-detector` / `ai-slopsquatting/2.0` | `pkgsentinel` / `pkgsentinel/<ver>` | 도구 브랜드 정리 |
| `KEYRING_SERVICE` | (결정 필요: 유지 vs `pkgsentinel`+마이그레이션) | §위험 |
| `ttp_id="AISLOPSQ-CLS"` / `AISLOPSQ-{rule}` | `AGENTIC-CLS` / `AGENTIC-{rule}` | evidence |
| `llm_model="aislopsq-classifier"/"aislopsq-rules"` | `agentic-classifier` / `agentic-rules` | evidence |
| `rule_kind="aislopsq_r"` | `agentic_r` | runtime_intel DB |
| `generate_aislopsq_r_extension`, `_aislopsq_dotenv` | `generate_agentic_r_extension`, `_acm_dotenv` | 내부 심볼 |
| `docs/aislopsq/` | `docs/agentic-manifest/` | git mv + 링크 수정 |
| `AISLOPSQ-MANIFEST-SPEC.md` | `AGENTIC-CAPABILITY-MANIFEST-SPEC.md` | git mv |
| prose "AISLOPSQ" | "Agentic Capability Manifest" | 표시 문구 |

## 실행 순서 (eval 완료 후)

1. **저위험 먼저** (역할 7): 주석/문서/내부 심볼 — 회귀 위험 0
2. **문서 이동** (역할 4 docs): `git mv docs/aislopsq docs/agentic-manifest`, 스펙 파일명, 내부 링크
3. **매니페스트 키 alias** (역할 1·2): `manifest.py` 의 reader 가 `agentic` 우선,
   없으면 `aislopsq` fallback. writer/표기는 `agentic`. → `test_agentic` 회귀
4. **wire 헤더 alias** (역할 3): `server/app.py` `_get_signature_headers` 가
   `X-PkgSentinel-*` 우선, 없으면 `X-AISLOPSQ-*`. webhook 송신은 신규. → sink 테스트
5. **툴 브랜드** (역할 4 strings): `ai-slopsquatting*` → `pkgsentinel`. STIX/VEX/Falco
   vendor 출력 → 포맷 테스트 회귀
6. **evidence ID** (역할 6): `AISLOPSQ-*` → `AGENTIC-*`. → verdict/agentic 테스트
7. **키링** (역할 5): **별도 결정** (아래)

각 단계 후 `pytest` + `ruff` 회귀.

## 결정 필요 (실행 전 확인)

1. **매니페스트 키를 `agentic` 로?** — `[tool.agentic]` 제안. 다른 선호(`[tool.agent-capabilities]`)?
2. **OS 키링 서비스명 변경?** — 변경하면 기존 저장 키 조회 불가(재등록 필요).
   현 사용자≈0이면 변경 OK. 안전하게 **유지 + TODO** 도 가능.
3. **HTTP 헤더 prefix** — `X-PkgSentinel-*`(도구 브랜드) vs `X-ACM-*`(표준)?
   헤더는 *도구의 HMAC 프로토콜*이라 도구 브랜드(`X-PkgSentinel-*`)가 맞다고 봄.
4. **하위호환 alias 유지 기간** — 영구 vs deprecation 주기(예: v0.2까지)?

## 검증 (실행 후)
- `pytest tests/` 전체 (현 398 유지)
- `ruff check src tests scripts`
- 구 매니페스트 키 `[tool.aislopsq]` 가진 fixture 가 여전히 인식되는지(alias) 테스트 1개 추가
- 구 헤더 `X-AISLOPSQ-Signature` 로 보낸 요청이 여전히 인증되는지 테스트 1개 추가
