# 2026-05-06 프로젝트 재검토 — Fresh-Eyes Audit

> 본 세션의 4 PR 작업 + 프로젝트 전반 상태 + 위험/갭 + 다음 방향.
> 자기 작업의 비판적 재평가 포함.

---

## 0. 한 줄 평

> **이번 세션 FP 5건 정상화 (대단한 진전) — 그러나 동일 fix 가 합성 fixture 에서 recall 0.98 → 0.87 로 깎음 (FN 8건). 머지 전 카테고리 인식 STANDALONE_WEAK 로 정밀화 필수.**

---

## 1. 이번 세션 산출 (4 PR 요약)

| PR | 브랜치 | 변경 | 효과 |
|---|---|---|---|
| 1 | fix/...fp-reduction | converters/sequence_patterns/stage1*.py + 2 commits | 9-pkg verdict 7→5 HIGH_RISK |
| 2 | refactor/...pipeline-diet | pipeline.py + _stage_runner.py | -120 lines, 무동작 |
| 3 | chore/...fp-tooling | scripts + docs (24 신규 파일) | 분석 도구 4종 + 보고서 6편 |
| 4 | fix/...anomaly-categorization | anomaly + api_catalog + package_categories + 3 commits | pandas/numpy CLEAN + 카테고리 시스템 + UX 단순화 |

**검증된 효과**:
- 9-패키지 smoke (PR1∪PR4): **5 CLEAN, 3 HIGH_RISK, 1 SUSPICIOUS** (handoff 8 HIGH 대비 5건 정상화)
- LLM v2 잔존 FP 2건 (flask, fastapi) 모두 stub 모드에서 CLEAN
- 78 pytest pass

---

## 2. 🔴 Critical — 미공개 위험: Recall 회귀

### 정량 측정 (PR1 ∪ PR4 적용, 합성 fixture eval)

```
TP:  52   FN:   8     ← 진짜 악성 8건 놓침
FP:   0   TN:  60
Precision : 1.0000
Recall    : 0.8667    ← baseline 0.9833 대비 -0.12
F1        : 0.9286    ← baseline 0.9916 대비 -0.063
```

### 누락된 8 FN (진짜 악성 패턴!)

| Fixture | 누락 동력 |
|---|---|
| `obfuscated-import-exec` | DEF-006 + EXM-001 둘 다 STANDALONE_WEAK → BENIGN downgrade |
| `ssh-key-theft` | creds-paths + EXF-001 (STANDALONE_WEAK 추가) → BENIGN |
| `wallet-exfil` | SYS-003 단독 + 다른 weak |
| `credential-paths-multifile` | (분석 필요) |
| `chrome-cookie-stealer` | (분석 필요) |
| `node-ipc-style-geo-bomb` | (node-ipc 사건 재현 패턴) |
| `shai-hulud-self-replicate` | (자가복제 worm 패턴) |
| `browser-history-exfil` | (브라우저 히스토리 추출) |

### 근본 원인

PR1 의 STANDALONE_WEAK 확장 (EXM-008, EXS-002, EXM-006, EXF-001, SYS-001, NET-009, EXM-002, EXM-003, SYS-002, NET-010 추가) + PR4 의 SP-005 LOW 강등 + SP-003 INFO 가드 + api_catalog 에서 expanduser 제거.

**모두 popular-benign 코퍼스의 FP 줄이기가 목표였지만 unknown 패키지 (= 합성 fixture 처럼 분류 안 된 신규/typosquat 패키지) 의 진짜 악성 신호도 같이 약화시킴**.

### 해결 방향 (3 옵션)

| 옵션 | 변경 폭 | 장단 |
|---|---|---|
| **A. 부분 롤백** | 작음 | EXF-001 / SYS-003 같은 명백한 위험 신호는 STANDALONE_WEAK 에서 제거 |
| **B. 카테고리 인식 STANDALONE_WEAK** | 중간 | broad-purpose 패키지 한정으로 STANDALONE_WEAK 확장 적용. unknown 패키지엔 보수적 정책 |
| **C. 문맥 부스트** | 큼 | STANDALONE_WEAK 라도 의심 string (~/.ssh/, AWS_ACCESS_KEY_ID, wallet.dat) 동반 시 escalate |

**제 추천: B + 부분적으로 A**:
- B: PR1 의 STANDALONE_WEAK 확장을 카테고리 인식으로 — `if is_broad_purpose: extra_weak += {EXM-008, EXS-002, ...}`
- A: EXF-001, SYS-003 같은 명백한 신호는 어떤 패키지든 weak 처리 X

이러면 합성 fixture (unknown 카테고리) 에서 Recall 회복 + popular-benign 에서 FP 억제 동시 달성.

---

## 3. 🟠 High — 다른 위험들

### 3.1 4 PR 통합 미테스트
- PR1 ∪ PR4 머지 시 sequence_patterns.py conflict 발생 (해결법 문서화됨)
- PR1 ∪ PR2, PR3 ∪ 나머지 등 다른 조합 미검증
- **권장**: 머지 전 staging 브랜치에서 4개 다 합쳐서 78 pytest + eval_synthetic 재실행

### 3.2 `evidence.llm_verdict` 의 misleading 이름
- rule-based 로 set 됨 (converters.py)
- 실제 Stage 5 LLM 의 합의 결과 ≠ evidence.llm_verdict
- LLM v2 측정에서 fastapi `llm_stub: benign` 인데 verdict HIGH_RISK 인 이유 — 이 misleading naming 의 결과
- **리팩터 후보** (PR5 가능): `evidence.rule_severity` + `evidence.llm_consensus` 분리. 큰 변경.

### 3.3 Stage 4 (TTP 임베딩 매칭) 의 효과 미검증
- sentence-transformers 로 MITRE TTP 와 임베딩 유사도
- 하지만 측정한 fixture (django/numpy 등) 에서 `ttp_match: 0` 다수
- 캐시 빌드 + 임계 조정 없으면 실효성 적음
- 또 CI 격리 (heavy dep) 라 회귀 안 잡힘

### 3.4 카테고리 시스템 단위 테스트 부재
- `package_categories.py` 80+ 패키지 매핑 + 25+ phrase 룰
- pytest 테스트 0개 → 회귀 위험
- **즉시 추가 권장**: `tests/test_package_categories.py`

---

## 4. 🟡 Medium

### 4.1 합성 fixture 의 4:1 mal:ben 비율
- 100 mal + 20 benign — 운영 prevalence (1:30,000) 와 5만배 어긋남
- F1 metric 자체가 신뢰도 낮음
- **권장**: stratified eval — Recall_on_mal + FP_rate_on_benign 분리

### 4.2 합성 fixture 가 web_framework / data_science 양성 샘플 부족
- benign 20개 중 대부분 단순 utility (json-helper, url-builder, hash-utility 등)
- 진짜 web_framework 양성 샘플 없음 → fastapi 같은 패턴 회귀 catch 불가
- **권장**: benign 에 mini flask/numpy/pytest 같은 fixture 추가

### 4.3 pipeline.py 970+ lines (PR2 후도)
- 미변환 11 stage 잠재력 ~70 lines 추가 절감
- early-return 패턴 헬퍼 추가 후 가능

### 4.4 `_pipeline_state.PipelineContext` 비대화
- 9개 필드 (ext, behavior, diff, description, archive_sha256, category, ...)
- 새 stage 추가 시마다 또 비대해짐
- **고려**: stage 별 결과를 별도 dataclass 로 — `ctx.stages.behavior`, `ctx.stages.diff`

---

## 5. 🟢 Low — 정리 / 메타

### 5.1 README 미업데이트
- 새 PackageCategory 시스템, FP 개선 측정값, legitimate_tool 필드 등 미반영
- cost_model.md 수치 (handoff doc 기준) 도 PR1+4 적용 후 재산정 필요

### 5.2 handoff doc 미갱신
- `docs/2026-05-06-todo.md` 가 다음 세션 시작점
- 이번 세션의 산출 / 미해결 / 권장 작업 반영 필요

### 5.3 .gitignore 정리
- PR3 에서 `cache_lite/` 추가됨, 그러나 다른 산출물 (`smoke_anomaly_fix.json` 등) 은 검토 필요

---

## 6. 프로젝트 전반 — 잘 된 점 (객관적)

### 아키텍처
- 9-stage 명확한 분리, evidence-based reasoning
- 다층 지식 (MITRE ATT&CK / ATLAS, OWASP LLM, SLSA, SSDF, GHSA, OSV)
- 멀티-LLM 합의 (Anthropic + OpenAI), AISLOPSQ Manifest 차별화
- 암호화 위협 DB (sqlcipher + master_key + integrity 3중)
- stage_cache (오늘의 ebde138 commit) 으로 반복 분석 절감

### 엔지니어링
- pyproject.toml + 4개 console scripts
- CI 매트릭스 (Ubuntu/Win × Py 3.11/3.12) + CodeQL + pip-audit
- Apache-2.0 + CONTRIBUTING + SECURITY 표준 준수
- 78 pytest (heavy 3개 격리)
- ruff + mypy 적용, type hints 일관

### 차별화
- AISLOPSQ Manifest 표준 제안
- 47-indicator + 6 sequence pattern + taint slicer + multi-agent
- file-local risk_combo escalation (오늘의 commit `82335e7`)
- 실시간 모니터 (PyPI/npm watcher → priority queue → 3종 sink)

---

## 7. PR 머지 권장 순서 (재정의)

이전 권장 (PR2 → PR1 → PR4 → PR3) 에 **§2 의 recall 회귀** 반영해 수정:

### Step A — 머지 전 (필수)
1. **§2 옵션 B (카테고리 인식 STANDALONE_WEAK) 적용** → eval_synthetic 재측정 → R≥0.95 회복 확인
2. **package_categories 단위 테스트 추가**
3. **PR4 의 sequence_patterns.py merge conflict 해결** (PR1과 합쳐 staging 브랜치 작성)

### Step B — 머지 (위 통과 후)
4. PR2 (refactor) — 안전, 무동작
5. PR1 (verdict) — 카테고리 인식 패치 적용된 상태
6. PR4 (category) — PR1 위에서 효과 큼
7. PR3 (docs/tools) — 마지막 (다른 PR 의 보고서 참조)

### Step C — 머지 후
8. README + cost_model + handoff doc 갱신
9. webpack 잔존 HIGH_RISK 분석 (별도 PR)
10. eval_real.py 인스트루멘테이션 (별도 PR)

---

## 8. 전략적 결정 사항 (사용자)

### 즉시 결정 필요
- **(D-1)** §2 의 fix — A / B / C 중 어떤 옵션? **B 강력 추천**
- **(D-2)** 머지 전 staging 브랜치 만들어 통합 테스트 ? (Step A-3)
- **(D-3)** 4 PR 모두 머지 vs 일부 보류? (recall 회귀 해결 전엔 PR1 머지 위험)

### 단기 (다음 세션)
- **(D-4)** webpack FP 시도 vs 정리/문서화 우선?
- **(D-5)** `evidence.llm_verdict` 리팩터 (큰 변경) 시도?

### 중장기
- **(D-6)** Stage 4 TTP 임베딩의 실효성 측정 — heavy dep CI 통합 방향?
- **(D-7)** eval 코퍼스 확장 (web_framework benign + 더 큰 corpus)?

---

## 9. 한 줄 결론 재확인

> **5건 verdict 정상화는 진짜 진전. 그러나 합성 fixture 의 ssh-key-theft / wallet-exfil 같은 명백한 악성 8건을 놓침이 정량 확인됨. PR1 의 STANDALONE_WEAK 확장을 카테고리 인식으로 정밀화하는 게 머지 전 최우선. eval_synthetic 회귀 측정 안 하고 머지하면 큰 위험.**

---

## 10. 이 보고서의 한계

- 합성 fixture (120 sample) 만 측정. 실 데이터 (eval_real_data 의 550) 미측정.
- LLM 모드 효과 미측정 (API 키 없음, 비용 우려)
- webpack / requests / react 같은 잔여 HIGH_RISK 의 root-cause 분석 일부만
- pipeline.py 미변환 11 stage 의 변환 이득 추정만, 실측 안 함
