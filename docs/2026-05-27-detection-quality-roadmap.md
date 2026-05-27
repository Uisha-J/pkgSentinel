# 2026-05-27 — 탐지 품질 로드맵: 과적합 해소 + 미구현 지표 13종

본 문서는 두 가지 미해결 문제의 해결방안을 설계한다.

1. **데이터 과적합** — 합성 fixture P=1.000 R=0.983 vs 실데이터 P=0.962
   R=0.731. 이 격차는 매처가 자기가 평가받는 데이터에 맞춰졌다는 신호.
2. **49 카탈로그 중 13 미구현 지표** — matcher 없이 카탈로그에만 존재하는
   13개 코드의 처리 방안.

---

## 파트 1 — 데이터 과적합

### 1.1 증상 (현재 수치)

| 평가셋 | P | R | F1 | 비고 |
|---|---|---|---|---|
| 합성 fixture (cycle 11) | 1.000 | 0.983 | 0.992 | 작성자가 직접 만든 120 fixture |
| 실데이터 (n=550) | 0.962 | 0.731 | 0.831 | DataDog malicious dataset 등 |
| 실 인기 패키지 (numpy/django 등 9개) | — | — | — | **8/9 FP** (직접 측정) |

R 0.983 → 0.731 의 25%p 하락, 그리고 평가셋 benign FP 14% vs 실제 인기
패키지 FP 88% 의 격차가 과적합의 핵심 증거.

### 1.2 근본 원인

1. **train/test 미분리** — 매처 튜닝에 쓴 fixture 와 성능 보고에 쓴 fixture
   가 동일. cycle 1→11 동안 "fixture 결과 보고 매처 조정" 을 반복한 것은
   정의상 그 fixture 에 fitting 한 것.
2. **합성 fixture 를 튜너가 작성** — 매처가 검사하는 가정과 fixture 가
   인코딩한 가정이 같음. (매처가 `base64+requests` 를 찾으면, fixture 도
   `base64+requests` 로 작성됨 → 항상 맞음)
3. **eval-time 룰이 점수에 섞임** — `scripts/eval_real.py` 의 popular×benign
   다운그레이드가 평가 점수를 높이지만 production 코어에는 없음(의도적으로
   제거함). 즉 보고된 P=0.96 은 production 이 내지 못하는 수치.
4. **benign 셋이 너무 쉬움** — 평가 benign 은 단순 패키지 위주. 실제 CI
   에 깔리는 numpy/django/webpack 같은 "dangerous-API 합법 다용" 패키지가
   과소대표됨.

### 1.3 해결방안 (우선순위 순)

#### S-1. Hold-out 규율 (필수, 즉시)
- fixture 를 `dev/` (튜닝 허용) 와 `test/` (측정 전용, 절대 안 봄) 로 분리.
- **헤드라인 지표는 test 셋에서만 보고.** dev 셋 수치는 "개발 중 참고용"
  으로 명시.
- 구현: `scripts/eval_synthetic.py` 에 `--split {dev,test,all}` 추가,
  fixture json 에 `"split"` 필드. 매처 변경 후엔 dev 로 반복, 릴리스
  직전 1회만 test.

#### S-2. 외부 독립 데이터셋 (필수)
- 작성자가 만들지 않은 데이터로 측정 — 이미 부분 사용 중인 자산 확대:
  - **DataDog `malicious-software-packages-dataset`** (이미 `3857e0e` 에서 사용)
  - **Backstabber's Knife Collection** (학술 표준 malware corpus)
  - **OSV malicious advisories** (`feeds/osv.py` 가 이미 수집)
  - **PyPI/npm 실 benign top-N** (numpy/django/webpack 등 FP 유발 패키지 포함)
- 이 셋들에 **튜닝 금지** — 측정만. 외부셋 수치를 README 헤드라인으로.

#### S-3. Temporal split (권장)
- 특정 날짜 이전 공격으로 튜닝, 이후 공격으로 test. 실제 배포(미래의 신종
  공격 탐지) 를 시뮬레이션. zero-day 탐지(Z1-Z6) 의 진짜 일반화 능력 측정.

#### S-4. Realistic negative set (필수)
- benign 셋에 **실제 FP 유발 패키지**(numpy, pandas, django, flask, react,
  webpack, scipy, tensorflow, lxml, cryptography 등) 를 명시적으로 포함.
- 목표: 이 셋에서 FP rate < 10% 가 될 때까지 매처(eval 룰 아님) 개선.

#### S-5. Eval 룰과 코어 분리 보고 (필수)
- `eval_real.py` 의 popular×benign 다운그레이드를 켠 수치와 끈 수치를
  **둘 다** 보고. 끈 수치(= production 코어가 실제 내는 값) 가 정직한 헤드라인.
- 장기적으로 popular 다운그레이드는 평가에서도 제거하고, FP 는 매처/LLM
  으로 해소 (인기도 축이 아니라 — 2026-05-06 결정 참고).

#### S-6. Ablation + per-matcher 기여도 (권장)
- 각 매처를 하나씩 끄고 P/R 변화 측정. 특정 fixture 에만 반응하는
  과적합 매처를 가시화. `scripts/eval_synthetic.py --ablate <CODE>`.

#### S-7. Pre-registration (권장)
- 매처 룰을 freeze → 그 다음 fresh test 셋 1회 측정 → 그 수치를 고정 보고.
  사후 튜닝 유혹 차단.

### 1.4 수용 기준 (Definition of Done)
- 외부 독립셋(S-2) + realistic negative(S-4) 에서 측정한 P/R/F1 이
  README 헤드라인. 합성 fixture 수치는 "단위 회귀 베이스라인" 으로 강등 표기.
- 실 인기 패키지 9종 FP rate < 10% (현재 88%).

---

## 파트 2 — 미구현 지표 13종

### 2.1 식별된 13개 (카탈로그 49 ∖ matcher 36)

| 코드 | sev | 이름 | 정적 탐지 가능성 |
|---|---|---|---|
| EXF-002 | HIGH | File Exfiltration | ★★★ 높음 (taint 인프라 재사용) |
| NET-004 | HIGH | Archive Dropper | ★★★ 높음 (download+extract AST) |
| NET-005 | HIGH | Binary Dropper | ★★★ 높음 (download+chmod/exec) |
| NET-006 | HIGH | Payload Dropper | ★★★ 높음 (install-hook download+exec) |
| SYS-008 | MEDIUM | Arbitrary File Write | ★★★ 높음 (open(w) 민감경로) |
| SYS-006 | MEDIUM | File Relocation | ★★☆ 중간 (shutil.move 은닉경로) |
| MET-002 | MEDIUM | Combosquatting | ★★★ 높음 (이름+popular affix) |
| MET-006 | HIGH | Metadata Typosquatting | ★★★ 높음 (편집거리 1~2 vs popular) |
| DEF-004 | HIGH | Encryption Obfuscation | ★★☆ 중간 (crypto import+exec) |
| DEF-002 | MEDIUM | Computational Obfuscation | ★☆☆ 낮음 (entropy 휴리스틱, FP多) |
| NET-003 | HIGH | Suspicious Connection | ★☆☆ 낮음 (도메인 평판 intel 필요) |
| DEF-001 | MEDIUM | ASCII Art Deception | ☆☆☆ 정적 불가 (의도 이해 필요) |
| MET-005 | MEDIUM | Decoy Functionality | ☆☆☆ 정적 불가 (의미 이해 필요) |

### 2.2 3-Tier 처리 전략

#### Tier 1 — 정적 구현 (8종, 즉시 착수)
가장 가치 높고 tractable. 기존 인프라 재사용:

- **EXF-002**: `taint_slicer` 의 source 에 `open().read()` / dir-walk 추가,
  sink 는 기존 network. 이미 H-2 에서 with-as seed 구현했으니 확장 용이.
- **NET-004/005/006 (dropper 3종)**: `indicator_matcher._match_from_sequence`
  에 "download API (urllib/requests/httpx.get) → {zipfile/tarfile.extract |
  chmod+x | open(wb)+exec | os.system}" 시퀀스 추가. setup.py/install-hook
  컨텍스트면 severity ↑.
- **SYS-006/008**: `open(path,'w'|'wb')` / `shutil.move` / `os.rename` 의
  대상이 민감·영구·은닉 경로(`~/.bashrc`, `/etc`, `.ssh`, `AppData`,
  cron, `.` 숨김파일) 인 경우. AST 인자 상수 분석.
- **MET-002/006 (combosquat/typosquat)**: `_match_from_metadata` 에 패키지명
  vs `knowledge` 의 popular 명단 편집거리(Levenshtein ≤2) + affix 결합
  검사. **주의: 여기서의 "popularity" 는 타이포스쿼팅 탐지용 신호(정당)**
  — verdict 의 인기도-신뢰 금지 원칙과 무관 (스쿼팅 대상 식별용).

각 구현마다 **외부셋(파트1 S-2)으로 검증** — 자작 fixture 로만 맞추지 말 것.

#### Tier 2 — 휴리스틱 구현 + FP 경고 (3종)
- **DEF-004**: `cryptography`/`Crypto`/`Fernet` import + decrypt 호출 결과를
  `exec/eval` 에 전달하는 흐름. taint 로 연결 가능. FP: 정당한 암호화 라이브러리.
- **DEF-002**: 비트연산/문자열연산 밀도 + 결과 exec. entropy 휴리스틱.
  **FP 위험 높음** → severity MEDIUM 유지 + standalone-weak 등록.
- **NET-003**: 코드 내 하드코딩 IP/도메인 리터럴 추출까지는 정적. 도메인
  나이/평판은 `feeds` 의 위협 intel(feodo/urlhaus) 와 조인. intel 미가용 시
  LOW 로 degrade.

#### Tier 3 — 정적 불가 → 명시적 재분류 (2종)
- **DEF-001 (ASCII art)** / **MET-005 (decoy functionality)**: 의도/의미
  이해가 필요해 패턴 매칭 불가. **카탈로그에서 "LLM-scoped" 로 태깅** →
  Stage 5 LLM 프롬프트에 해당 항목을 명시적으로 질의. 정적 matcher 는
  만들지 않되 "미구현" 이 아니라 "LLM 담당" 으로 정직하게 표기.

### 2.3 결과 표기 (정직성)
구현 후 카탈로그 상태를 3분류로 명시:
```
49 indicators total
  ├─ 44 static matchers (36 기존 + 8 Tier1)
  ├─  3 heuristic matchers (Tier2, FP 주의 표기)
  └─  2 LLM-scoped (Tier3, 정적 미탐지 — Stage 5 위임)
```
README 의 "49/36" 를 위 3분류로 교체 → "미구현 13" 이라는 모호한 표현 제거.

### 2.4 구현 순서 (제안)
1. MET-002/006 (typosquat) — 독립적, 인프라 영향 최소, 즉시 가치
2. NET-004/005/006 (dropper) — sequence matcher 확장, 공통 패턴
3. EXF-002 + SYS-006/008 — taint/AST 인자 분석 확장
4. Tier2 3종 — 휴리스틱, FP 측정하며 신중히
5. Tier3 2종 재분류 — 카탈로그 메타데이터 + LLM 프롬프트 1줄씩

각 단계: 구현 → **외부셋 검증** → fixture 는 dev/test 분리 → 회귀 확인.

---

## 두 파트의 연결

**핵심: 미구현 지표 13종을 구현할 때 파트1 의 과적합 규율을 반드시 적용.**
새 matcher 를 자작 fixture 로만 검증하면 또 과적합이 재생산된다. Tier1/2
구현은 외부 독립셋(S-2) + realistic negative(S-4) 로 검증해야 하며, 그래야
"13개 채웠는데 실데이터 성능은 그대로" 를 피할 수 있다.
