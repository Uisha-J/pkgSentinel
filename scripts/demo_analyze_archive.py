"""[DEMO ONLY — 배포 비포함] 로컬 패키지 *아카이브* 분석 도구.

━━ 배포 분리 (이 파일을 따로 만든 이유) ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  - 이 스크립트는 `scripts/` 에 있다. `pyproject.toml` 의
    `[tool.setuptools.packages.find]` 는 `src/pkgsentinel*` 만 패키징하므로,
    `scripts/` 는 wheel/sdist (= `pip install`) 에 **절대 포함되지 않는다.**
  - 따라서 배포 시 별도 제거 작업이 필요 없다. 그냥 빠진다.
  - 코어(`src/pkgsentinel/`)는 한 줄도 수정하지 않았다. 데모 로직은 전부 여기 격리.
  - 정 배제하고 싶으면 이 파일 하나만 지우면 끝 (`scripts/demo_analyze_archive.py`).

━━ 왜 필요한가 ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  Shai-Hulud 처럼 레지스트리에서 unpublish 된 악성 패키지는 라이브 CLI
  (`pkgsentinel <pkg>`) 로 받을 수 없다 — 정리된 최신 버전이 와서 CLEAN 이 뜬다.
  이 도구는 *보존된 아카이브*(예: DataDog malicious-software-packages-dataset,
  password-zip 'infected') 의 로컬 바이트를 실제 엔진 매처/판정에 그대로 흘려보내,
  진짜 악성 코드를 근거와 함께 시연한다.

  ※ 분석 경로는 run_pipeline 의 로컬-분석 가능 단계(behavior/string/TTP/anomaly/
    indicator/sequence/LLM)와 동일한 *공개 함수*를 재사용한다. 레지스트리 조회·
    다운로드·캐시·바이너리·샌드박스 단계만 생략한다.

사용:
  python scripts/demo_analyze_archive.py <archive> --ecosystem npm \\
      [--name @ctrl/tinycolor] [--version 4.1.2] \\
      [--zip-password infected] [--format auto] [--llm stub|claude] [--json]

예 (DataDog 보존 샘플):
  python scripts/demo_analyze_archive.py sample.zip -e npm \\
      --name @crowdstrike/glide-core --version 0.34.2 --zip-password infected
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "scripts"))

from pkgsentinel import _dotenv

_dotenv.load()

# Windows 콘솔(cp949) 에서도 리포트의 유니코드(박스/한글/—)가 깨지지 않도록.
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[attr-defined]
    except Exception:
        pass

import eval_real  # 같은 scripts/ — 아카이브 추출 로직(zip+password 포함) 재사용

from pkgsentinel.evidence.converters import (
    anomaly_to_evidence,
    indicator_hit_to_evidence,
    sequence_match_to_evidence,
    sstr_to_evidence,
)
from pkgsentinel.evidence.snippets import find_file_seq, match_confidence, snippet_for
from pkgsentinel.knowledge.anomaly_baseline import detect_anomalies
from pkgsentinel.reporting.formats import format_report
from pkgsentinel.schema import Ecosystem, Evidence, StageResult, empty_report
from pkgsentinel.stages.indicator_matcher import match_all as match_47
from pkgsentinel.stages.sequence_patterns import mine as mine_seq
from pkgsentinel.stages.stage2_behavior import analyze as analyze_behavior
from pkgsentinel.stages.stage4_ttp_match import match_ttps
from pkgsentinel.stages.stage5_llm_review import review
from pkgsentinel.stages.string_analysis import analyze_strings
from pkgsentinel.verdict_rules import decide_verdict


def _detect_format(path: str, override: str | None, zip_password: str | None) -> str:
    if override and override != "auto":
        return override
    if zip_password:
        return "zip+password"
    low = path.lower()
    if low.endswith((".tar.gz", ".tgz")):
        return "tar.gz"
    if low.endswith(".whl"):
        return "wheel"
    if low.endswith(".zip"):
        return "zip"
    return "tar.gz"  # 기본 추정


class _ExtLike:
    """Stage 2 analyze() 가 기대하는 entry_files 보유 객체 (run_pipeline 과 동일 패턴)."""
    entry_files: list


def analyze_local_files(
    name: str,
    ecosystem: str,
    version: str,
    files: dict[str, str],
    llm_mode: str = "stub",
):
    """{path: content} → 실제 엔진 매처/판정으로 AnalysisReport 생성.

    run_pipeline 의 로컬-분석 단계 순서(08/09/11/12/13/14/16 + verdict)를 그대로
    따른다. decide_verdict 는 필수 stage (08/11/16) 의 success 를 본다.
    """
    eco = Ecosystem(ecosystem)
    report = empty_report(name, eco, version or "unknown")
    evidence: list[Evidence] = []
    stages: list[StageResult] = []

    entries = eval_real._files_to_entry(files)
    fulls = eval_real._files_to_full_source(files)

    # ── Stage 08: Behavior Sequence (필수) ──
    try:
        ext = _ExtLike()
        ext.entry_files = entries
        behavior = analyze_behavior(ext)
        stages.append(StageResult(
            stage="stage_08_behavior_sequence", success=True,
            payload={"files": len(behavior.files),
                     "calls": len(behavior.all_calls())},
        ))
    except Exception as e:
        stages.append(StageResult(
            stage="stage_08_behavior_sequence", success=False, error=str(e)))
        report.verdict = decide_verdict(evidence, stages, registry_found=True)
        report.stage_results = stages
        return report

    # ── Stage 09: 문자열 상수 풀 ──
    try:
        n_str = 0
        for sf in fulls:
            if sf.language not in ("python", "javascript"):
                continue
            strs = analyze_strings(sf.path, sf.content, sf.language)
            if strs:
                n_str += len(strs)
                evidence.extend(sstr_to_evidence(sf.path, strs))
        stages.append(StageResult(
            stage="stage_09_string_analysis", success=True,
            payload={"suspicious_strings": n_str}))
    except Exception as e:
        stages.append(StageResult(
            stage="stage_09_string_analysis", success=False, error=str(e)))

    # ── Stage 11: TTP 매칭 (필수) ──
    try:
        match_report = match_ttps(behavior, top_k=3)
        stages.append(StageResult(
            stage="stage_11_ttp_matching", success=True,
            payload={"matches": len(match_report.matches)}))
    except Exception as e:
        stages.append(StageResult(
            stage="stage_11_ttp_matching", success=False, error=str(e)))
        report.verdict = decide_verdict(evidence, stages, registry_found=True)
        report.stage_results = stages
        report.evidence = evidence
        return report

    # ── Stage 12: 카테고리 이상 탐지 ──
    try:
        findings = detect_anomalies(name, "", behavior.files)
        for f in findings:
            evidence.append(anomaly_to_evidence(f))
        stages.append(StageResult(
            stage="stage_12_anomaly_detection", success=True,
            payload={"anomalies": len(findings)}))
    except Exception as e:
        stages.append(StageResult(
            stage="stage_12_anomaly_detection", success=False, error=str(e)))

    # ── Stage 13: 47-indicator 매처 (file-local escalation 동일) ──
    try:
        ind = match_47(
            behavior_files=behavior.files, source_files=fulls,
            package_name=name, description="", author="", declared_deps=[])
        codes_per_file: dict[str, set[str]] = {}
        for h in ind.hits:
            codes_per_file.setdefault(h.file_path, set()).add(h.indicator.code)
        for h in ind.hits:
            evidence.append(
                indicator_hit_to_evidence(h, codes_per_file.get(h.file_path, set())))
        stages.append(StageResult(
            stage="stage_13_indicator_matcher", success=True,
            payload={"hits": len(ind.hits), "high": ind.high_severity_count}))
    except Exception as e:
        stages.append(StageResult(
            stage="stage_13_indicator_matcher", success=False, error=str(e)))

    # ── Stage 14: Sequential pattern mining ──
    try:
        seq = mine_seq(behavior)
        for m in seq.matches:
            evidence.append(sequence_match_to_evidence(m))
        stages.append(StageResult(
            stage="stage_14_sequence_mining", success=True,
            payload={"patterns": len(seq.matches)}))
    except Exception as e:
        stages.append(StageResult(
            stage="stage_14_sequence_mining", success=False, error=str(e)))

    # ── Stage 16: LLM 이중 검증 (필수) — TTP 매치별 ──
    try:
        for m in match_report.matches:
            fs = find_file_seq(behavior, m.file_path)
            if fs is None:
                continue
            snippet = snippet_for(fs)
            try:
                llm = review(
                    name, version or "unknown", eco.value, fs,
                    match_report.matches, snippet, mode=llm_mode)
            except Exception:
                continue
            evidence.append(Evidence(
                file_path=fs.path,
                line_start=fs.calls[0].line if fs.calls else 0,
                line_end=fs.calls[-1].line if fs.calls else 0,
                code_snippet=snippet[:1500],
                behavior_sequence=list(fs.sequence),
                attack_dimensions=list(fs.dimensions),
                ttp_id=m.ttp.ttp_id, ttp_name=m.ttp.ttp_name,
                ttp_source=m.ttp.source, ttp_url=m.ttp.url,
                ttp_severity=m.ttp.severity, vector_similarity=m.similarity,
                llm_verdict=llm.verdict, llm_reasoning=llm.reasoning,
                llm_model=llm.model,
                confidence=match_confidence(m, llm.verdict)))
        stages.append(StageResult(
            stage="stage_16_llm_review", success=True,
            payload={"mode": llm_mode, "evidence": len(evidence)}))
    except Exception as e:
        stages.append(StageResult(
            stage="stage_16_llm_review", success=False, error=str(e)))

    report.verdict = decide_verdict(evidence, stages, registry_found=True)
    report.evidence = evidence
    report.stage_results = stages
    report.package_meta = {
        "source": "LOCAL ARCHIVE (demo_analyze_archive — not a registry download)",
        "files_analyzed": len(files),
    }
    return report


_USE_COLOR = sys.stdout.isatty()
_RESET = "\033[0m" if _USE_COLOR else ""

def _c(code: str) -> str:
    return code if _USE_COLOR else ""

# 시연 가시성 우선 — MALICIOUS 는 흰 글씨 + 빨간 배경 + 볼드 (강한 강조)
_VERDICT_COLOR = {
    "MALICIOUS":      _c("\033[1;97;41m"),  # bold white on red bg
    "HIGH_RISK":      _c("\033[1;91m"),     # bold bright red
    "SUSPICIOUS":     _c("\033[1;93m"),     # bold bright yellow
    "AGENTIC":        _c("\033[1;96m"),     # bold bright cyan
    "CLEAN":          _c("\033[1;92m"),     # bold bright green
    "ERROR":          _c("\033[1;91m"),
    "CANNOT_ANALYZE": _c("\033[1;95m"),     # bold bright magenta
}
_LLM_COLOR = {
    "malicious":  _c("\033[1;91m"),  # bold bright red
    "suspicious": _c("\033[1;93m"),  # bold bright yellow
    "benign":     _c("\033[2m"),     # dim
}
_SEV_COLOR = {
    "HIGH":   _c("\033[1;91m"),
    "MEDIUM": _c("\033[1;93m"),
    "LOW":    _c("\033[2m"),
}


def _print_demo_summary(report, top_n: int) -> None:
    """녹화용 간결 뷰: verdict + evidence 요약 + 결정적 근거 Top-N.

    번들/난독화 파일은 high-entropy 문자열을 수백~수천 개 쏟아내므로(대부분
    LOW/BENIGN, 판정엔 영향 없음) 전체 덤프(format_report) 대신 강한 신호만 추린다.
    Verdict / llm_verdict / severity 는 ANSI 컬러로 강조 (TTY 일 때만).
    """
    from collections import Counter

    ev = report.evidence
    sev = dict(Counter(e.ttp_severity.value for e in ev))
    llmv = dict(Counter(e.llm_verdict.value for e in ev))
    vstr = report.verdict.value
    vcol = _VERDICT_COLOR.get(vstr, "")
    # MALICIOUS 는 배경색이라 양옆 공백을 줘서 좀 더 도드라지게
    pad = " " if vstr == "MALICIOUS" else ""
    print("=" * 70)
    print(f"Package : {report.package} {report.version} ({report.ecosystem.value})")
    print(f"Verdict : {vcol}{pad}{vstr}{pad}{_RESET}")
    print("=" * 70)
    print(f"\n[Evidence 요약] total={len(ev)} | severity={sev} | llm={llmv}")

    decisive = sorted(
        (e for e in ev
         if e.ttp_severity.value == "HIGH"
         or e.llm_verdict.value in ("malicious", "suspicious")),
        key=lambda e: e.confidence, reverse=True,
    )
    print(f"\n[결정적 근거 Top {min(top_n, len(decisive))} / {len(decisive)}]")
    for i, e in enumerate(decisive[:top_n], 1):
        lc = _LLM_COLOR.get(e.llm_verdict.value, "")
        sc = _SEV_COLOR.get(e.ttp_severity.value, "")
        print(f"\n  #{i}  [{lc}{e.llm_verdict.value}{_RESET} · "
              f"{sc}{e.ttp_severity.value}{_RESET} · conf {e.confidence:.2f}]  "
              f"{e.file_path} (L{e.line_start})")
        print(f"      {e.ttp_id} — {e.ttp_name}")
        seq = " -> ".join(e.behavior_sequence[:6])
        if seq:
            print(f"      seq: {seq}")
        if e.llm_reasoning:
            print(f"      why: {e.llm_reasoning[:160]}")
    if not decisive:
        print("  (결정적 근거 없음 — 약한 신호만)")


def main() -> None:
    ap = argparse.ArgumentParser(
        description="[DEMO] 로컬 패키지 아카이브를 실제 엔진으로 분석 (배포 비포함)")
    ap.add_argument("archive", help="분석할 로컬 아카이브 경로 (.tar.gz/.tgz/.zip/.whl)")
    ap.add_argument("--ecosystem", "-e", choices=["PyPI", "npm"], required=True)
    ap.add_argument("--name", default=None, help="패키지명 라벨 (기본: 파일명)")
    ap.add_argument("--version", default="unknown")
    ap.add_argument("--zip-password", default=None,
                    help="암호화 zip 비밀번호 (DataDog 샘플은 'infected')")
    ap.add_argument("--format", default="auto",
                    choices=["auto", "tar.gz", "tgz", "zip", "wheel", "zip+password"])
    ap.add_argument("--label", choices=["malicious", "benign"], default="malicious",
                    help="malicious=전 파일 스캔(악성 샘플 시연용, 기본) / "
                         "benign=test·dist·번들 제외")
    ap.add_argument("--llm", choices=["stub", "claude"], default="stub",
                    help="Stage 16 모드 (기본 stub — 오프라인·무료·결정적)")
    ap.add_argument("--top", type=int, default=8,
                    help="요약 뷰에 보일 결정적 근거 개수 (기본 8)")
    ap.add_argument("--full", action="store_true",
                    help="전체 evidence 덤프 (format_report). 번들 파일은 수천 줄 주의")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()

    path = Path(args.archive)
    if not path.is_file():
        print(f"ERROR: 파일 없음: {path}", file=sys.stderr)
        sys.exit(2)

    name = args.name or path.stem
    fmt = _detect_format(str(path), args.format, args.zip_password)
    if args.zip_password:
        eval_real.ZIP_PASSWORD = args.zip_password.encode()

    data = path.read_bytes()
    # label="malicious" → 추출 시 test/dist 등 스킵 없이 전 파일 분석 (악성은 어디 숨었는지 모름)
    files = eval_real.extract_archive(data, fmt, label=args.label)
    if not files:
        print(
            f"ERROR: 분석 가능한 소스 파일이 없습니다 (format={fmt}). "
            f"--format / --zip-password 를 확인하세요.", file=sys.stderr)
        sys.exit(1)

    report = analyze_local_files(
        name=name, ecosystem=args.ecosystem,
        version=args.version, files=files, llm_mode=args.llm)

    if args.json:
        print(report.to_json())
    else:
        print(f"\n[DEMO] LOCAL ARCHIVE 분석 - {path.name} "
              f"(format={fmt}, {len(files)} source files, llm={args.llm})")
        if args.full:
            print(format_report(report))
        else:
            _print_demo_summary(report, args.top)
        # 오용 방지 — 이 도구는 레지스트리/인기도/threat-filter 컨텍스트가 없다.
        # 알려진 악성 샘플 시연 전용. 정상 패키지는 stub 모드에서 과탐(FP)한다.
        print(
            "\n[주의] 이 도구는 *로컬 아카이브만* 분석합니다 — 레지스트리 조회·"
            "인기도 다운그레이드·threat-filter 컨텍스트가 없습니다.\n"
            "        용도는 'unpublish 되어 라이브로 못 받는 악성 샘플' 시연입니다.\n"
            "        정상 패키지 비교(CLEAN)는 라이브 `pkgsentinel <pkg> -e ... --llm claude` 를 쓰세요 "
            "(stub 모드는 인기 패키지 FP 가 높음).")


if __name__ == "__main__":
    main()
