# 2026-05-27 — 실데이터 4-cell 평가 (stub/claude × ON/OFF, n=543)

S-5 토글로 측정. **OFF = production verdict_rules 경로(출하 엔진이 실제 내는 값)**,
**ON = eval 다운그레이드 휴리스틱 적용(그동안 보고된 수치)**.

데이터: DataDog malicious 454 (malicious_intent 400 + compromised_lib 54) +
registry benign 89. claude = Sonnet 4.5 LAMPS 3-agent.

## 4-cell

| | OFF (출하 엔진) | ON (eval 하니스) |
|---|---|---|
| **stub** | P 0.851 · R 0.703 · F1 0.770 · FP 56 | P 0.944 · R 0.667 · F1 0.782 · FP 18 |
| **claude** | P 0.865 · R **0.793** · F1 0.828 · FP 56 | P **0.994** · R 0.773 · F1 0.870 · FP 2 |

(benign 89 기준 FP율: stub-OFF 63% / stub-ON 20% / claude-OFF 63% / claude-ON 2%)

## 핵심 결론 3가지

### 1. LLM의 실제 기여 = recall, precision 아님
- OFF recall: stub 0.703 → claude **0.793** (+0.090). LLM이 정적 분석이 놓친 악성을 잡음.
  - malicious_intent recall 0.642 → 0.762 (+0.120)
- OFF precision: 0.851 → 0.865 (**+0.014**, 거의 변화 없음). **LLM은 production 경로의
  benign FP 문제를 못 고침** — 정상 패키지 63%(56/89)를 여전히 오탐.

### 2. 광고된 "FP 13→2 / P 0.99"는 엔진이 아니라 eval 하니스
- claude ON P=0.994, FP=2 ← LLM-mode 보고서가 낸 수치.
- claude OFF(production) P=0.865, FP=56. **격차 +0.129 = eval 다운그레이드 룰**
  (특히 Rule C: popular + LLM-benign → CLEAN).
- 즉 `python -m pkgsentinel.cli` 가 실제 내는 건 P 0.865 / FP 56이지, 0.99/2가 아님.
- claude의 S-5 격차(+0.129)가 stub(+0.093)보다 **더 큼** → claude 헤드라인 precision이
  하니스 보정에 더 의존.

### 3. 사건 패키지(compromised_lib) recall = 0.852 (46/54)
- stub·claude 동일. Shai-Hulud / TanStack 등 실제 침해 패키지는 안정적으로 잡힘.
- 이게 도구의 핵심 가치 명제("유명 패키지 공격 탐지")를 뒷받침.

## 발표 어필에 대한 함의 (정직한 재조정)

직전 "3-agent 검증이 유효하다" 어필을 데이터에 맞춰 정직하게:

- ✅ **방어 가능**: "LLM 3-agent 검증이 recall을 70%→79%로 올린다 — 패턴 매칭이
  놓친 악성 코드를 잡는다." (OFF recall 0.703→0.793 = 엔진의 진짜 이득)
- ⚠️ **과장 금지**: "FP를 2개로 줄였다 / P 0.99"는 **eval 후처리 휴리스틱**이지 코어
  엔진이 아님. 발표에서 이걸 엔진 성능으로 말하면 S-5 정직성과 모순.
- 권장 문구: "LLM 검증은 recall을 +9pt 올린다. 정밀도(FP) 개선의 상당 부분은 코어가
  아닌 평가단 후처리에서 나오며, 우리는 이를 투명하게 분리해 보고한다."

## 품질 검증 (WiFi 블립 영향)
- ERROR fixture 6/543 (1.1%, 추출 실패 — WiFi 무관 추정)
- 정상 89개 전부 LLM=benign 정확 분류
- 악성 중 LLM=benign 31% — 기존 zero-signal POC 모집단과 일치. WiFi 폴백과
  데이터상 구분 불가하나, **OFF recall이 stub 대비 상승**한 사실이 폴백이 경미함을 시사.
- **결론: 결과 사용 가능. claude recall(0.793)은 약간의 과소추정일 수 있음(WiFi 폴백
  일부 가능성) — 방향성 유리(실제 ≥ 측정).**

## 측정 메타
- stub: 449s (8 worker), claude: 3227s (4 worker, ~54분), claude 비용 ≈ $29
- 토글: `--eval-rules {on,off}` (dual-emit, 단일 실행으로 ON/OFF 동시 산출)
