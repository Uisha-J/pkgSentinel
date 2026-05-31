# 학술 자료 → 코드/설계 영향 매핑

> 본 프로젝트가 인용한 외부 자료(논문/표준/도구/데이터)가 **어느 코드/설계에 어떻게 반영**됐는지 역방향 인덱스.
>
> 원본 출처 표 + 본문은 `docs/references/` (54건), `docs/aislopsq/` (Manifest 표준).
> 본 문서는 그 위에 "영향" 한 줄 요약 + 코드 위치를 더한다.
>
> 영향 유형 표기:
> - **A** Algorithm/Pattern — 핵심 아이디어 차용
> - **D** Data Catalog — 직접 데이터/룰 적재
> - **T** Threshold/Heuristic — 수치/임계값 결정 근거
> - **F** Framework Mapping — 표준 매핑 (verdict / TTP)
> - **L** Library — 직접 사용
> - **E** Evaluation Dataset — 측정 데이터
> - **C** Citation Only — 정당성 부여 (코드 미반영)

---

## 1. 학술 논문 (9 본문 + 11 부록 = 20편)

### 1.1 핵심 차용 ★

| # | 논문 | 영향 | 영향 위치 |
|---|---|---|---|
| L01 | **Unveiling Malicious Logic** (arXiv 2512.12559, 2025) | A+D | `src/pkgsentinel/knowledge/malicious_indicators.py` — **47개 지표 × 7 카테고리 택소노미 전체 적재**. `stages/sequence_patterns.py` — Sequential pattern mining 알고리즘 |
| L02 | **Cerebro — Behavior Sequence** (ACM TOSEM, DOI 10.1145/3705304, 2025) | A | `stages/api_catalog.py` — **4 Attack Dimension (INFO/ENCODE/EXEC/TRANSMIT) 개념 직접 도입**. `stages/stage2_behavior.py` — Tree-sitter 기반 AST behavior sequence 추출 |
| L03 | **DONAPI** (USENIX Security 2024, arXiv 2403.08334) | D | `stages/api_catalog.py` — 132 native API 카탈로그 구조 차용 (현재 ~80 entries) |
| L04 | **Taint-Based Code Slicing for LLMs** (arXiv 2512.12313, 2025) | A | `stages/taint_slicer.py` — **LLM 에 전체 코드 대신 taint slice 만 전달**. Stage 5 프롬프트 토큰 ~50% 절감 |
| L05 | **LAMPS — Multi-Agent** (arXiv 2601.12148, 2025) | A | `stages/stage5_multi_agent.py` — **3 에이전트 (semantic / diff / dependency) consensus 구조** |
| L06 | **Mind the Gap** (arXiv 2602.16304, 2025) | A | Stage 5 LLM 프롬프트 이분화 (고수준 verdict / fine-grained indicator) 설계 |
| L07 | **NPM Benchmark** (arXiv 2603.27549, 2025) | E | `scripts/eval_real_data/` — 6,420 mal + 7,288 ben 벤치마크. `benchmarks/harness.py` 평가 하니스 |
| L08 | **Robust Industry Detection** (arXiv 2409.09356, 2024) | T | 산업 환경 낮은 FP 율 튜닝 방법론 → STANDALONE_WEAK 정책 + 카테고리 baseline (`evidence/converters.py`) |
| L09 | **We Have a Package for You** (USENIX Security 2024) | C | 19.7% LLM 환각률 수치 → **프로젝트 정당성** (슬롭스쿼팅 위협의 정량적 근거) |

### 1.2 부록 (보조 인용)

| # | 논문 | 영향 |
|---|---|---|
| L10 | Library Hallucinations (arXiv 2509.22202, 2025) | C — 환각 사례 실증 |
| L11 | Metadata Information 탐지 (arXiv 2402.07444) | A — MET 카테고리 6개 지표 (`malicious_indicators.py` MET-001~006) |
| L12 | SCORE — Syntactic Code Repr (arXiv 2411.08182) | C — 정적 표현 차원 비교 |
| L13 | Knowledge-Mining PyPI (arXiv 2601.16463) | C — 지식 그래프 접근 비교 대상 |
| L14 | Empirical Study of Malicious Code in PyPI | E — 실증 사례 인용 |
| L15 | ML-Based PyPI Detection (RG 386555242) | C — 비교 대상 |
| L16 | Your Agent Is Mine (arXiv 2604.08407) | C — Manifest 의 supply-chain 중간자 시나리오 정당성 |
| L17 | Supply-Chain Poisoning Against LLM Coding (arXiv 2604.03081) | C — Manifest 차별화 (코딩 에이전트 skill ecosystem 공격) |
| L18 | Importing Phantoms (arXiv 2501.19012) | C — 환각 vulnerability 측정 |
| L19 | Robust/Adaptive Detection (arXiv 2512.04338) | C — 적응형 탐지 비교 |

### 1.3 AISLOPSQ Manifest 표준 전용 (5편) ★

| # | 논문 | 매핑 |
|---|---|---|
| M01 | **Chhabra et al. Survey 2025** (arXiv 2510.23883) | Step 1 (agentic 4요소 정의: planning + tool use + memory + autonomy), R3 (capability 분류), R2-1 (autonomy 공격 표면), R4-2 (memory poisoning), R4-4 (multi-agent collusion) |
| M02 | **Beurer-Kellner et al. 2025** (arXiv 2506.08837) | R1 전반 — design pattern (Dual LLM / Plan-Then-Execute / Action-Selector / Map-Reduce / Context-Minimization) |
| M03 | **Shi et al. ToolHijacker 2025** (arXiv 2504.19793) | R1-2 (tool selection 무결성), R4-5 (description-behavior mismatch) |
| M04 | **Nasr et al. Attacker Moves Second 2025** (arXiv 2510.09023) | "filtering 신뢰성 없음" → Manifest 사전 검증 정당화 |
| M05 | **Meta AI Rule of Two** (blog Oct 2025) | Step 3 Rule of Two, R2-1 Lethal Trifecta (A/B/C 3속성) |

→ 매핑 상세는 `docs/aislopsq/papers/INDEX.md` 의 역방향 인덱스.

---

## 2. 공식 표준 / 프레임워크 (11건)

| # | 표준 | 영향 | 영향 위치 |
|---|---|---|---|
| S01 | **NIST SP 800-218 SSDF v1.1** ★ | F+D | `stages/stage_ssdf.py` — **11개 SSDF 항목 자동 평가** (PO.4.1, PS.1.1, PS.2.1, PS.3.1, PW.4.1/4.4/4.5, PW.7.1, PW.8.1, RV.1.1, RV.2.1) |
| S02 | NIST SP 800-218A (AI 모델 SSDF) | C | 정부 공식 LLM 공급망 인식 — 프로젝트 정당성 |
| S03 | **MITRE ATT&CK** ★ | F+D | `knowledge/mitre_attack.py` — **568 techniques 자동 수집**. 모든 Evidence 의 `ttp_id` 가 MITRE ID (T1027, T1041, T1048, T1059, T1105, T1552 등 주요 매핑) |
| S04 | MITRE ATLAS (AI 시스템 TTP) | F | `knowledge/mitre_atlas.py` — 9 ATLAS 기법 카탈로그 (AML.T0010, .T0019, .T0020 슬롭스쿼팅 직접 매칭) |
| S05 | **OWASP Top 10 for LLM** | F | `knowledge/owasp_llm.py` — 10 카테고리 + `map_verdict_to_owasp()`. LLM05 (Supply Chain) + LLM09 (Overreliance) 슬롭스쿼팅 매핑 |
| S06 | **OWASP Top 10 for Agentic Applications** (2025-12) | F | AISLOPSQ Manifest R3 (Tool Misuse / Privilege Abuse) 직접 매핑 |
| S07 | **SLSA v1.0** ★ | F | `stages/stage_slsa.py` — npm provenance + PEP-740 attestations → L0/L1/L2/L3+ 평가 |
| S08 | CISA — Securing the Software Supply Chain (2024) | C | 미 연방 공식 지침 인용 — 권위 확보 |
| S09 | **OpenSSF Scorecard** ★ | F+L | `stages/stage_scorecard.py` — Scorecard API 호출 + risk signal 추출 (Maintained / Code-Review / Branch-Protection / Token-Permissions / Vulnerabilities 등 임계값 미달 검사) |
| S10 | OpenSSF OSPS Baseline (2024) | C | SSDF + Scorecard 교차 매핑 정당성 |
| S11 | GUAC (OpenSSF) | C | SBOM + SLSA + Scorecard 통합 가능성 — 향후 작업 |
| S12 | **CycloneDX VEX** | F+L | `stages/stage_vex.py` — **AnalysisReport → CycloneDX v1.5 + VEX JSON 직렬화**. analysis.state 매핑 (exploitable / in_triage / not_affected) |
| S13 | SPDX | C | 대체 SBOM 표준 — 향후 호환 작업 |
| S14 | OWASP Top 10 (웹) | C | 일반 웹 취약점 참고 |
| S15 | CVSS (FIRST) | C | 향후 severity 정규화 후보 |

---

## 3. 데이터 소스 (8건)

| # | 소스 | 영향 | 영향 위치 |
|---|---|---|---|
| D01 | **MITRE STIX CTI** (github.com/mitre/cti) ★ | D | `knowledge/mitre_attack.py` 자동 pull → `cache/mitre_attack.json` (431 techniques) → embedding `cache/mitre_attack_embedded.json` |
| D02 | MITRE ATLAS 공식 데이터 | D | `knowledge/mitre_atlas.py` 9 ATLAS 기법 |
| D03 | **OSV** (osv.dev) ★ | D | `knowledge/osv.py` → `cache/osv_pypi.json` (11,276 advisory), `cache/osv_npm.json` (212,686) |
| D04 | **GitHub Advisory (GHSA)** | D | `stage0b_attack_history.py` — 공급망 공격 이력 매칭 |
| D05 | OpenSSF Scorecard API (api.securityscorecards.dev) | D | Scorecard Stage 0C 에서 라이브 호출 |
| D06 | npm registry (registry.npmjs.org) | D | Stage 0/1 메타데이터 + tarball |
| D07 | PyPI JSON API (pypi.org/pypi/.../json) | D | Stage 0/1 메타데이터 + sdist URL |
| D08 | **hugovk/top-pypi-packages + anvaka/npmrank** | D | `feeds/popular.py` + `scripts/build_popular_benign.py` — 인기 패키지 baseline / benign 코퍼스 |

---

## 4. 사용 도구 / 라이브러리 (10건)

| # | 도구 | 영향 |
|---|---|---|
| T01 | **Tree-sitter** (+ tree-sitter-javascript) ★ | L — `stages/js_ast_parser.py` JS AST 파싱 |
| T02 | **Sentence-Transformers** (`all-MiniLM-L6-v2`) ★ | L — `knowledge/embedder.py` MITRE TTP 임베딩 + 코사인 유사도 검색 |
| T03 | pgvector (PostgreSQL 벡터 검색) | C — 향후 대규모 인덱스 |
| T04 | Qdrant | C — pgvector 대안 |
| T05 | **Anthropic Claude** (claude-sonnet-4-5) ★ | L — Stage 5 LLM review + multi-agent consensus |
| T06 | **OpenAI** (GPT-4o) | L — multi-agent consensus 보조 |
| T07 | **sqlcipher3** | L — `db/threat_db.py` 암호화 위협 DB |
| T08 | **pefile / pyelftools** | L — `stages/stage_binary.py` PE/ELF 분석 |
| T09 | **rapidfuzz** | L — `stage0_threat_filter.py` 타이포스쿼팅 편집거리 매칭 |
| T10 | **httpx / aiohttp** | L — 레지스트리 / Scorecard API 호출 |

---

## 5. 산업 보고서 (11건)

| # | 출처 | 영향 |
|---|---|---|
| I01 | **Socket** (슬롭스쿼팅 해설, Chrome Extension) | C+A — 슬롭스쿼팅 용어 정의, Chrome Ext 차별화 (우리는 VSCode + 풀 분석 엔진) |
| I02 | **Snyk** (패키지 환각 + 완화 전략 + Snyk DB) | C — 위협 모델 검증 |
| I03 | **Datadog Security Labs** (MUT-8694 / macOS) ★ | E — **합성 fixture (eval_real_data) 의 datadog/malicious_intent 50건 출처** |
| I04 | **Sonatype** (OSS Index, 연례 State of SSC) | C — 산업 동향 |
| I05 | **GitGuardian** (Hard-coded Secrets) | C — credential 탐지 정당성 |
| I06 | **Phylum** (악성 패키지 모니터링) | C — 경쟁/비교 |
| I07 | **Endor Labs** (Reachability Analysis) | C — 의존성 도달성 분석 |
| I08 | **Wiz** (SLSA Glossary) | C — SLSA 정리 인용 |
| I09 | **Aqua Security** (Trivy + 공급망 보고서) | C — SBOM 시장 |
| I10 | **Checkmarx** (SCA blog) | C — SAST/SCA 산업 위치 |
| I11 | **OX Security / Chainguard** (정리 블로그) | C — SLSA/SSDF 해설 |

---

## 6. 유사/경쟁 프로젝트 (5건)

| # | 프로젝트 | 영향 |
|---|---|---|
| P01 | **Socket Security** | C — 경쟁 (Chrome Ext + cloud 분석) |
| P02 | **Snyk** | C — 경쟁 (DB + IDE 통합) |
| P03 | **OpenSSF Allstar / Scorecard** | L (S09 와 동) |
| P04 | **OSSF Package Analysis** | D — `stages/stage_sandbox.py` 의 데이터 소스 (대안 sandbox 정보) |
| P05 | **GitGuardian / Trufflehog** | C — secret scan 비교 |

---

## 7. 코드 모듈 역방향 인덱스

각 코드 모듈이 인용하는 주요 자료:

| 모듈 | 인용 |
|---|---|
| `knowledge/malicious_indicators.py` | L01 (47 지표 택소노미) + L11 (MET 6 카테고리) |
| `knowledge/mitre_attack.py` + `cache/mitre_attack.json` | S03 + D01 |
| `knowledge/mitre_atlas.py` | S04 + D02 |
| `knowledge/owasp_llm.py` | S05 + S06 (Agentic Top 10) |
| `knowledge/embedder.py` | T02 (Sentence-Transformers) |
| `knowledge/osv.py` + `cache/osv_*.json` | D03 |
| `stages/api_catalog.py` | L02 (4 Dimension) + L03 (132 API) |
| `stages/stage2_behavior.py` | L02 + T01 (Tree-sitter) |
| `stages/stage3b_full_diff.py` | event-stream/colors.js/eslint-scope 사건 (산업 보고서 인용) |
| `stages/stage4_ttp_match.py` | S03 + T02 (임베딩 매칭) |
| `stages/sequence_patterns.py` | L01 (Sequential Pattern Mining) |
| `stages/taint_slicer.py` | L04 |
| `stages/stage5_llm_review.py` + `stage5_multi_agent.py` | L05 (LAMPS) + L06 (Mind the Gap) + T05/T06 |
| `stages/stage_scorecard.py` | S09 + D05 |
| `stages/stage_slsa.py` | S07 |
| `stages/stage_ssdf.py` | S01 |
| `stages/stage_vex.py` | S12 |
| `stages/stage_binary.py` | T08 (pefile/pyelftools) |
| `stages/stage_sandbox.py` | P04 (OSSF Package Analysis) |
| `stage0_threat_filter.py` | D03 + D04 + T09 (rapidfuzz) |
| `feeds/popular.py` | D08 |
| `evidence/converters.py` (STANDALONE_WEAK / risk_combo) | L08 (Robust Industry FP 튜닝) |
| `verdict_rules.py` | L08 + L05 (multi-agent consensus → verdict) |
| `benchmarks/harness.py` | L07 (NPM Benchmark) |
| `db/threat_db.py` | T07 (sqlcipher3) |
| `agentic/` (AISLOPSQ 전체) | M01~M05 + S06 (OWASP Agentic Top 10) |

---

## 8. 발표용 어필 (1슬라이드 요약)

> **총 54건의 외부 공식 자료**를 인용. 그 중:
> - **학술 논문 20편** (2024~2026년 발표 6편)
> - **공식 표준 11건** (NIST / MITRE / OWASP / SLSA / OpenSSF / CISA)
> - **AISLOPSQ Manifest 표준은 5편의 핵심 논문 + 7건의 외부 표준** 의 모든 룰을 역방향 인덱스로 매핑 (`docs/aislopsq/papers/INDEX.md`)
> - 모든 verdict 의 TTP 매핑은 **공식 자료 원문 인용** (MITRE STIX CTI, OSV, GHSA 자동 수집)

### 직접 차용 핵심 4편 ★
1. **Unveiling Malicious Logic** (2025) → 47 지표 × 7 카테고리 (`malicious_indicators.py`)
2. **Cerebro** (TOSEM 2025) → 4 Attack Dimension + Behavior Sequence (`api_catalog.py`)
3. **Taint Slicing for LLMs** (2025) → LLM 비용 ~50% 절감 (`taint_slicer.py`)
4. **LAMPS Multi-Agent** (2025) → 3 에이전트 consensus (`stage5_multi_agent.py`)

### 표준 통합 핵심 6건
1. **NIST SSDF v1.1** — 11 항목 자동 평가 (`stage_ssdf.py`)
2. **MITRE ATT&CK** — 568 techniques (`mitre_attack.py`)
3. **MITRE ATLAS** — 9 AI/LLM TTP (`mitre_atlas.py`)
4. **OWASP LLM Top 10** + **Agentic Top 10** — verdict 매핑 (`owasp_llm.py`)
5. **SLSA v1.0** — provenance 평가 (`stage_slsa.py`)
6. **CycloneDX VEX** — SBOM 직렬화 (`stage_vex.py`)
