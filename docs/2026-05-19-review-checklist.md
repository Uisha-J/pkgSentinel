# AISLOPSQ_REVIEW 대응 체크리스트

외부 코드리뷰(`AISLOPSQ_REVIEW.txt`) 기반. 각 항목은 (1) 현재 코드 검증 → (2) 수정 → (3) 재검증 사이클로 처리한다.

상태 표기: `[ ]` 미해결 / `[~]` 진행 / `[x]` 해결 / `[N/A]` 코드로 해결 불가(문서화로 대체)

---

## CRITICAL — 운영 보안 (즉시)

- [ ] **C-1. 서버 fail-open** — `_get_secret()` None 반환 + `check_hmac` shared_secret None 시 무조건 통과 + 기본 bind `0.0.0.0`.
  - 검증: `server/app.py:60`, `api/auth.py:98`, `server/__main__.py:24` — 모두 확인됨.
  - 수정: prod 모드에서 secret 미설정이면 fail-closed(요청 거부). 기본 bind `127.0.0.1`. 명시적 opt-in(`PKGSENTINEL_DEV_NO_AUTH=1`)일 때만 인증 skip.
- [ ] **C-2. iocs export GET 인증 우회** — `app.py:159-162` GET 시 signature/secret 전부 None 전달 → 항상 통과 → 위협 인텔 유출.
  - 검증: 확인됨.
  - 수정: GET도 HMAC 적용(쿼리스트링 정규화 후 동일 검증) 또는 GET 제거. secret 설정 시 GET도 인증 강제.

## HIGH — manifest 면책 악용 (Part 2 패치 제공됨)

- [ ] **M-A. 자기선언 면책 차단 (Part 2-A)** — `session_isolation` / `design_patterns` 선언이 코드 시그니처로 검증될 때만 심각도 완화. 미검증 선언은 `DECLARED-BUT-UNVERIFIED` 기록만.
  - 검증: `rule_of_two.py:27-29`(is_violation), `rules.py:182-245`(R1 면책), `rules.py:309-319`(R2-1 면책) — 전부 미검증 선언으로 완화됨.
  - 수정: `verify_session_isolation()`, `verify_design_patterns()` 추가 + 효과 게이팅.
- [ ] **M-B. satisfies 비교 구현 (Part 2-B)** — `rule_of_two.satisfies`가 파싱만 되고 판정에 안 쓰이는 죽은 코드.
  - 검증: `rules.py`에 satisfies 비교 없음 확인.
  - 수정: `R3_rule_of_two_consistency()` 추가 — detected ABC ⊄ declared → SUSPICIOUS, declared=={A,B,C} → HIGH_RISK.

## HIGH — 정확성

- [ ] **H-6. MALICIOUS 게이트 평균→max** — `verdict_rules.py:183` 평균 confidence ≥ 0.85 → 저신뢰 지표 하나로 조용히 강등.
  - 검증: `_avg_confidence(evidence) >= MALICIOUS_CONFIDENCE_THRESHOLD` 확인됨.
  - 수정: high-severity 매칭의 max confidence 기준으로 변경.

## MEDIUM — manifest 룰 품질 (1.5.5)

- [ ] **Q-1. R1-4 getattr FP** — `getattr(module, tool_name)(...)` 정규식이 모든 동적 getattr를 flag (rules.py:172).
  - 수정: LLM 출력/원격 입력 변수와 결합될 때만 매칭하도록 좁힘.
- [ ] **Q-2. R4-3 substring FP** — 영속 메모리 + `logger/log` substring 부재면 전부 SUSPICIOUS (rules.py:589).
  - 수정: word-boundary 정규식 + provenance 시그니처 확대.
- [ ] **Q-3. R4-5 benign-verb substring** — `v in fn_name` 이라 `widget/target/budget`이 "get"으로 오분류 (rules.py:498).
  - 수정: word-boundary 매칭.
- [ ] **Q-4. capability_detector 우선순위** — `name==sig or A and B` 묶임 모호 (capability_detector.py:250).
  - 수정: 명시적 괄호.
- [ ] **Q-5. 스키마 검증 (1.5.3a)** — declared capability가 canonical 15종 어휘인지 미검증 → 오타가 영원히 불일치.
  - 수정: `_from_dict`에서 canonical 어휘 검증 + 비정규 항목 경고/무시.
- [ ] **Q-6. manifest-부재 FP 폭탄 (1.5.4)** — manifest 없으면 declared=∅ → undeclared dangerous → 즉시 MALICIOUS 단축 (classifier.py:132).
  - 수정: manifest 부재 시 dangerous-undeclared를 즉시-MALICIOUS가 아닌 R3 룰 경로(증거 누적)로 강등.

## MEDIUM — 기타 코드 결함

- [ ] **B-1. pipeline ctx.description 버그** — `info.get("ctx.description")` (pipeline.py:448, 739) → PyPI 메타는 `description` 키라 영원히 빈 값. `[:200]` 슬라이스가 fallback에만 적용.
  - 수정: `info.get("description", "")` + 올바른 슬라이스.
- [ ] **B-2. OSV zip 폭탄** — `feeds/osv.py:267` 압축해제 크기 상한 없음.
  - 수정: per-file `file_size` 상한 + 누적 상한.
- [ ] **B-3. Docker 샌드박스 격리** — `--cap-drop`/`--pids-limit`/`--memory` 없음 (stage_sandbox.py:132,179,299).
  - 수정: 세 docker run에 `--cap-drop ALL --pids-limit --memory --cpus` 추가.

## HIGH — 문서 톤다운 (1.6 #4)

- [ ] **D-1. README/스펙 과장 수정** — "47 indicators"→"47 분류(N개 구현)", "세 겹 무결성"→"기본 1겹/paranoid 3겹", F1에 "합성 픽스처 기준" 단서, manifest를 "방어 layer"가 아닌 "투명성 표준"으로.

## N/A — 코드 패치로 해결 불가 (정직하게 문서화)

- [N/A] **1.5.2 위협 모델 역전** — manifest 작성자=공격자. "전부 declare → AGENTIC 세탁"은 Sigstore 서명 manifest + 외부 attestation 같은 구조 변경 필요. → 스펙에 "투명성 도구이며 보안 통제 아님" 명시.
- [N/A] **H-2 taint flow-insensitive** — 함수 스코프/flow-sensitive 재작성은 연구 수준. → 한계 문서화 + `with...as` seed만 부분 개선 검토.
- [N/A] **H-3 난독화 무력** — 정적 분석 본질적 한계. → sandbox 옵션 + 한계 문서화.
- [N/A] **H-4 ~15 미구현 지표** — 각 matcher 실제 구현은 대규모. → 톤다운(D-1) + 가능한 일부 구현.
- [N/A] **MEDIUM CI LLM 경로 미검증** — API 키 필요. → 톤다운 + mock 1개 통합 검토.

---

## 최종 상태 (사이클 종료 시점)

### 해결 완료 (코드 수정 + 테스트)

| 항목 | 상태 | 수정 위치 | 검증 |
|---|---|---|---|
| C-1 서버 fail-open | [x] | `server/app.py` `_auth_posture`, `__main__.py` bind 127.0.0.1 | test_failclosed_* 3건 |
| C-2 iocs GET 우회 | [x] | `server/app.py` GET도 query_string 서명 검증 | test_iocs_export_get_* 2건 |
| M-A 자기선언 면책 | [x] | `rule_of_two.verify_session_isolation`, `rules.verify_design_patterns` + 게이팅 | test_dual_llm_*, test_session_isolation_* 3건 |
| M-B satisfies 비교 | [x] | `rules.R3_rule_of_two_consistency` + run_all_rules/classifier 배선 | test_satisfies_* 2건 |
| H-6 MALICIOUS avg→max | [x] | `verdict_rules._max_malicious_confidence` | test_h6_strong_malicious_* |
| Q-1 R1-4 getattr FP | [x] | `rules._R1_4_PATTERNS` LLM/도구 변수로 한정 | (R1 테스트 회귀 통과) |
| Q-2 R4-3 provenance | [x] | `rules._R4_3_PROVENANCE_RE` 확대 + word-boundary | (R4 테스트 회귀 통과) |
| Q-3 R4-5 benign-verb | [x] | `rules._matches_benign_verb` 토큰 매칭 | test_q3_widget_* |
| Q-4 precedence | [x] | `capability_detector` 명시 괄호 | test_q4_subprocess_* |
| Q-5 스키마 검증 | [x] | `manifest.declared_set` canonical 필터 + `unknown_capabilities` | test_q5_unknown_* |
| Q-6 manifest-부재 FP폭탄 | [x] | `classifier` short-circuit + `R3_check` manifest 게이팅 | test_q6_manifest_* 2건 |
| B-1 ctx.description | [x] | `pipeline.py` 448/739 `description` 키 + 슬라이스 교정 | (전체 회귀 통과) |
| B-2 OSV zip 폭탄 | [x] | `feeds/osv.py` entry/total/ratio 상한 | (전체 회귀 통과) |
| B-3 Docker 격리 | [x] | `stage_sandbox.DOCKER_HARDENING` 3개 run 적용 | test_sandbox_strace 통과 |
| D-1 문서 톤다운 | [x] | README(지표 49/36·무결성 1겹·manifest 투명성·F1 단서), 스펙 위협모델 노트 | — |

**테스트: 397개 전부 통과. 신규 회귀 테스트 12개 추가. 내 변경 코드 ruff 0건.**

### 코드로 완전 해결 불가 (정직하게 문서화로 대체)

| 항목 | 처리 |
|---|---|
| 1.5.2 위협 모델 역전 | M-A 로 면책 악용은 차단(공격 표면 축소). 근본 해결은 Sigstore 서명 manifest + 외부 attestation 필요 → README + 스펙에 "투명성 도구, 보안 통제 아님" 명시. |
| H-1 "세 겹 무결성" 과장 | 무결성 구현은 유지(대규모 변경 회피), README 에 "기본 1겹 / paranoid 3겹" 정정. |
| H-2 taint flow-insensitive | **부분 해결**: 리뷰가 우선순위 #5에서 콕 집은 `with...as` seed 를 구현(`taint_slicer.visit_With`/`visit_AsyncWith`) + tainted receiver 메서드 호출(`data=f.read()`) 전파 추가. test_with_as_seeds_taint 로 검증. flow-insensitive/scope-blind 본체 재작성은 연구 수준이라 한계로 유지. |
| H-3 난독화 무력 | 정적 분석 본질적 한계 → sandbox 옵션 + 한계 유지. |
| H-4 13개 미구현 지표 | 카탈로그 49 / 활성 matcher 36 으로 정직하게 표기(D-1). 13개 matcher 실제 구현은 별도 대규모 작업. |
| H-4 라인단위 정규식 newline 우회 | 미수정(별도 작업). multiline 패턴 일부 존재. |
| CI LLM 경로 미검증 | API 키 필요 → README 에 "CI 는 unit 만, LLM/eval 은 수동" 명시. |
| pipeline 보일러플레이트 | 보안 무관 리팩터 → 미수행. |

### 리뷰 ↔ 프로젝트 재대조 결과

- 리뷰 권장 우선순위(1.6) **1~4 전부 해결**, 5의 코드 항목(MALICIOUS max, canonical 스키마, manifest-부재 재고)도 해결.
- 5의 비코드 항목(taint 재작성, CI LLM 통합)은 한계로 문서화.
- 리뷰가 "잘 된 것"으로 검증한 항목(웹훅 HMAC, 비실행 샌드박스, AST taint, SQLCipher, XSS 방어)은 그대로 유지 — 회귀 없음.
- Part 2-A / 2-B 패치는 현재 코드 구조에 맞춰 적용 완료 + 회귀 테스트로 의도 동작 확인.
