# -*- coding: utf-8 -*-
"""실험1 — 출하 엔진(run_pipeline + decide_verdict, 인기도 보정 없음) 정렬 측정.

캐시 아카이브를 run_pipeline 에 주입(check/extract_all monkeypatch)하여 정상·악성을
동일한 production 경로로 측정. per-file multi-agent + verdict_rules(B-to-SUSPICIOUS,
typosquat) 가 그대로 적용된다. ASCII 출력만 사용.

사용:
  PKGSENTINEL_LLM_MODE=claude python scripts/eval_prod.py --fixtures <combined.json> --json <out>
"""
from __future__ import annotations
import argparse, json, os, sys, time, traceback
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = ROOT / "scripts" / "eval_real_data"
sys.path.insert(0, str(ROOT / "src"))

from pkgsentinel.schema import Ecosystem, Verdict
import pkgsentinel.pipeline as P
from pkgsentinel.stages.stage1b_full_source import FullSourceExtract
from pkgsentinel.stages.stage0_registry import RegistryInfo

# 하버스의 검증된 추출 로직 재사용 (zip+password, tar.gz 등 처리)
import importlib.util
_er_spec = importlib.util.spec_from_file_location("_eval_real", ROOT / "scripts" / "eval_real.py")
_er = importlib.util.module_from_spec(_er_spec)
sys.modules["_eval_real"] = _er  # dataclass __module__ 해석 위해 등록
_er_spec.loader.exec_module(_er)
extract_archive = _er.extract_archive
files_to_full_source = _er._files_to_full_source

# 현재 패키지의 캐시 아카이브 컨텍스트 (run_pipeline 순차 호출이므로 전역 안전)
_CUR: dict = {}

_orig_check = P.check
_orig_extract = P.extract_all


def _patched_check(package, ecosystem):
    ver = _CUR.get("version") or "0.0.0"
    return RegistryInfo(found=True, latest_version=ver,
                        archive_urls={ver: "cached://local"}, raw_metadata={})


def _patched_extract_all(package, ecosystem, version, archive_url):
    files = _CUR["files"]
    fulls = files_to_full_source(files)
    return FullSourceExtract(
        package=package, ecosystem=ecosystem, version=version or "0.0.0",
        archive_url="cached://local",
        archive_size=_CUR.get("archive_size", 0),
        source_files=fulls,
        binary_files=[],
        all_file_names=list(files.keys()),
    )


def evaluate(meta) -> dict:
    eco = Ecosystem.PYPI if str(meta["ecosystem"]).lower() == "pypi" else Ecosystem.NPM
    apath = DATA_DIR / meta["archive_path"]
    t0 = time.time()
    try:
        ab = apath.read_bytes()
        files = extract_archive(ab, meta["archive_format"], meta["label"])
        if not files:
            return {"name": meta["name"], "label": meta["label"], "verdict": "ERROR",
                    "error": "no source files"}
        _CUR.clear()
        _CUR.update(files=files, version=meta.get("version"), archive_size=len(ab))
        rep = P.run_pipeline(meta["name"], eco, llm_mode=os.environ.get("PKGSENTINEL_LLM_MODE", "claude"),
                             force_rescan=True)
        v = rep.verdict.value
        ev = len(rep.evidence)
    except Exception as e:
        return {"name": meta["name"], "label": meta["label"], "verdict": f"ERR:{type(e).__name__}",
                "error": str(e)[:160], "tb": traceback.format_exc()[:300]}
    return {"name": meta["name"], "label": meta["label"], "verdict": v,
            "evidence": ev, "secs": round(time.time() - t0, 1)}


def is_detected(v: str) -> bool:
    return v in ("MALICIOUS", "HIGH_RISK", "SUSPICIOUS")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--fixtures", default=str(DATA_DIR / "pypi_combined_fixtures.json"))
    ap.add_argument("--json", default=str(DATA_DIR / "results_prod.json"))
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--only", default="", help="benign|malicious 필터")
    args = ap.parse_args()

    P.check = _patched_check
    P.extract_all = _patched_extract_all

    fx = json.load(open(args.fixtures, encoding="utf-8"))
    fixtures = fx["fixtures"] if isinstance(fx, dict) else fx
    if args.only:
        fixtures = [f for f in fixtures if f.get("label") == args.only]
    if args.limit:
        fixtures = fixtures[:args.limit]

    out = []
    for i, meta in enumerate(fixtures, 1):
        r = evaluate(meta)
        out.append(r)
        print(f"[{i}/{len(fixtures)}] {r['label']:9s} {r['name'][:30]:30s} -> {r['verdict']:14s} "
              f"ev={r.get('evidence','-')} {r.get('secs','')}s", flush=True)
        json.dump(out, open(args.json, "w"), indent=2)  # incremental save

    # 메트릭
    mal = [r for r in out if r["label"] == "malicious"]
    ben = [r for r in out if r["label"] == "benign"]
    tp = sum(1 for r in mal if is_detected(r["verdict"]))
    mal_an = [r for r in mal if not r["verdict"].startswith("ERR") and r["verdict"] != "CANNOT_ANALYZE"]
    fp = sum(1 for r in ben if is_detected(r["verdict"]))
    ben_an = [r for r in ben if not r["verdict"].startswith("ERR")]
    recall = tp / len(mal_an) if mal_an else 0
    prec = tp / (tp + fp) if (tp + fp) else 0
    f1 = 2 * prec * recall / (prec + recall) if (prec + recall) else 0
    summary = {"malicious_total": len(mal), "malicious_analyzable": len(mal_an),
               "TP": tp, "benign_total": len(ben), "benign_analyzable": len(ben_an),
               "FP": fp, "recall": round(recall, 4), "precision": round(prec, 4),
               "f1": round(f1, 4)}
    print("\nSUMMARY:", json.dumps(summary))
    out_obj = {"results": out, "summary": summary}
    json.dump(out_obj, open(args.json, "w"), indent=2)
    print("DONE", args.json)


if __name__ == "__main__":
    main()
