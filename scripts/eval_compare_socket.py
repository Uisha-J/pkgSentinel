"""Socket.dev API 측정 — 543 fixture stratified subset + agentic dataset.

Quota 500 한도.
  Task A subset (300) + Task C agentic (100) + 여유 (100)

Socket endpoints:
  GET  /v0/npm/{pkg}/{version}/score   — npm 단일
  POST /v0/purl                         — PyPI / batch (Package URL 형식)

verdict 변환:
  supplyChainRisk.score < 0.3 → MALICIOUS
  supplyChainRisk.score < 0.5 → SUSPICIOUS
  그 외 → CLEAN
  + critical/high alert 있으면 격상
"""
from __future__ import annotations

import argparse
import base64
import json
import os
import time
import urllib.parse
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# ─────────────── token / auth ───────────────

def _load_token() -> str:
    env_path = ROOT / ".env"
    if env_path.exists():
        for line in env_path.read_text(encoding="utf-8").splitlines():
            if line.startswith("SOCKET_API_TOKEN="):
                return line.split("=", 1)[1].strip()
    return os.environ.get("SOCKET_API_TOKEN", "")


def _auth_header() -> dict:
    token = _load_token()
    if not token:
        raise RuntimeError("SOCKET_API_TOKEN missing in .env or env")
    return {
        "Authorization": "Basic " + base64.b64encode(f"{token}:".encode()).decode(),
        "Accept": "application/json",
    }


# ─────────────── HTTP ───────────────

def _get_json(url: str, timeout: int = 30):
    req = urllib.request.Request(url, headers=_auth_header())
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, json.loads(r.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        return e.code, {"error": e.read().decode("utf-8", errors="ignore")[:300]}
    except Exception as e:
        return -1, {"error": str(e)}


def _post_json(url: str, body, timeout: int = 30):
    data = json.dumps(body).encode("utf-8")
    headers = {**_auth_header(), "Content-Type": "application/json"}
    req = urllib.request.Request(url, data=data, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.read().decode("utf-8")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", errors="ignore")[:300]
    except Exception as e:
        return -1, str(e)


def get_quota() -> dict:
    code, body = _get_json("https://api.socket.dev/v0/quota")
    return body if isinstance(body, dict) else {"error": str(body)}


# ─────────────── Score → verdict 변환 ───────────────

def score_to_verdict(score_data: dict) -> tuple[str, dict]:
    """Socket score → verdict 변환.

    핵심 신호:
      - supplyChainRisk.score (0~1, 낮을수록 위험)
      - quality / maintenance / vulnerability / license 도 있음
    """
    scr = (score_data or {}).get("supplyChainRisk", {}).get("score")
    if scr is None:
        return "UNKNOWN", {"raw": score_data}

    # malicious-only signal: supplyChainRiskIssueCritical / High 가 0이 아닐 때
    comps = (score_data or {}).get("supplyChainRisk", {}).get("components", {})
    critical = comps.get("supplyChainRiskIssueCritical", {}).get("value", 0)
    high = comps.get("supplyChainRiskIssueHigh", {}).get("value", 0)

    if critical > 0:
        verdict = "MALICIOUS"
    elif high > 0:
        verdict = "HIGH_RISK"
    elif scr < 0.5:
        verdict = "SUSPICIOUS"
    else:
        verdict = "CLEAN"

    return verdict, {
        "score": round(scr, 4),
        "critical_issues": critical,
        "high_issues": high,
    }


# ─────────────── npm score ───────────────

def get_npm_score(name: str, version: str = "latest") -> dict:
    safe = urllib.parse.quote(name, safe="@/")
    url = f"https://api.socket.dev/v0/npm/{safe}/{version}/score"
    code, body = _get_json(url)
    if code == 200:
        verdict, info = score_to_verdict(body)
        return {"status": code, "verdict": verdict, **info, "raw_score": body}
    return {"status": code, "verdict": "ERROR", "error": body}


# ─────────────── PyPI score via /purl ───────────────

def get_pypi_score(name: str, version: str | None = None) -> dict:
    """PyPI 는 /purl POST endpoint 사용."""
    purl = f"pkg:pypi/{name}"
    if version and version not in ("latest", "unknown"):
        purl = f"{purl}@{version}"

    url = "https://api.socket.dev/v0/purl"
    code, body = _post_json(url, {"components": [{"purl": purl}]})
    if code != 200:
        return {"status": code, "verdict": "ERROR", "error": body}
    # body 는 NDJSON 형태일 수 있음 — 첫 줄 파싱
    try:
        first_line = body.split("\n")[0] if isinstance(body, str) else ""
        data = json.loads(first_line) if first_line else {}
        score_data = data.get("score", {})
        verdict, info = score_to_verdict(score_data)
        return {"status": code, "verdict": verdict, **info, "raw_score": score_data}
    except Exception as e:
        return {"status": code, "verdict": "PARSE_ERROR", "error": str(e),
                "raw_body": str(body)[:400]}


def get_score(eco: str, name: str, version: str = "latest") -> dict:
    eco_l = eco.lower()
    if eco_l == "npm":
        return get_npm_score(name, version)
    return get_pypi_score(name, version)


# ─────────────── 측정 main ───────────────

def measure(fixtures: list[dict], out_path: Path,
            sleep_s: float = 0.5, quota_limit: int = 500) -> dict:
    print(f"\n=== Socket 측정 시작 ({len(fixtures)} 패키지) ===")
    q0 = get_quota()
    print(f"  starting quota: {q0}")

    results = []
    ok = 0; fail = 0
    used = 0

    for i, fx in enumerate(fixtures, 1):
        # quota 잔량 안전 체크 (50개마다)
        if i % 50 == 0:
            q = get_quota()
            remaining = q.get("quota", 0)
            print(f"  [{i}/{len(fixtures)}] quota remaining: {remaining}")
            if remaining < 5:
                print(f"  ⚠ quota 부족 (< 5), 측정 중단")
                break

        eco = fx.get("ecosystem", "?")
        name = fx.get("name", "?")
        version = fx.get("version", "latest")
        r = get_score(eco, name, version)
        used += 1
        item = {
            "name": name, "ecosystem": eco, "version": version,
            "label": fx.get("label"),
            "source": fx.get("source"),
            **r,
        }
        results.append(item)
        if r.get("verdict") not in ("ERROR", "PARSE_ERROR", "UNKNOWN"):
            ok += 1
        else:
            fail += 1

        if i % 25 == 0:
            print(f"  ... [{i}/{len(fixtures)}] ok={ok} fail={fail} "
                  f"used={used}")
        time.sleep(sleep_s)

    q1 = get_quota()
    print(f"\n  done. ok={ok} fail={fail}. quota: {q0} → {q1}")

    # confusion
    tp = fp = tn = fn = 0
    for r in results:
        v = r.get("verdict", "")
        is_pred = v in ("MALICIOUS", "HIGH_RISK", "SUSPICIOUS")
        is_true = (r.get("label") == "malicious")
        if v in ("ERROR", "PARSE_ERROR", "UNKNOWN"):
            continue
        if is_true and is_pred: tp += 1
        elif is_true: fn += 1
        elif is_pred: fp += 1
        else: tn += 1
    n = tp + fp + tn + fn
    p = tp / (tp + fp) if (tp + fp) else 0.0
    rcl = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = (2 * p * rcl / (p + rcl)) if (p + rcl) else 0.0
    print(f"\n  TP={tp} FP={fp} TN={tn} FN={fn}  "
          f"P={p:.4f} R={rcl:.4f} F1={f1:.4f}  n={n}")

    out = {
        "tool": "Socket.dev API",
        "fixtures": results,
        "metrics": {"tp": tp, "fp": fp, "tn": tn, "fn": fn,
                    "precision": round(p, 4), "recall": round(rcl, 4),
                    "f1": round(f1, 4), "n": n},
        "quota_used": used,
        "quota_start": q0, "quota_end": q1,
    }
    out_path.write_text(json.dumps(out, ensure_ascii=False, indent=2),
                        encoding="utf-8")
    print(f"  saved: {out_path}")
    return out


# ─────────────── stratified sample (Task A) ───────────────

def stratified_300(fixtures: list[dict], seed: int = 42) -> list[dict]:
    """543 → 300 stratified (compromised 50 + malicious_intent 200 + benign 50)."""
    import random
    rng = random.Random(seed)
    comp = [x for x in fixtures if x.get("source") == "datadog/compromised_lib"]
    mali = [x for x in fixtures if x.get("source") == "datadog/malicious_intent"]
    ben  = [x for x in fixtures if x.get("source") == "registry"]
    rng.shuffle(comp); rng.shuffle(mali); rng.shuffle(ben)
    return comp[:50] + mali[:200] + ben[:50]


# ─────────────── main ───────────────

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--mode", choices=["taskA", "taskC", "quota"], required=True)
    ap.add_argument("--fixtures", default=str(ROOT / "scripts" / "eval_real_data" / "fixtures.json"))
    ap.add_argument("--out", default=None)
    ap.add_argument("--sleep", type=float, default=0.5)
    args = ap.parse_args()

    if args.mode == "quota":
        print(json.dumps(get_quota(), indent=2)); return

    if args.mode == "taskA":
        fx = json.loads(Path(args.fixtures).read_text(encoding="utf-8"))["fixtures"]
        sample = stratified_300(fx)
        out = Path(args.out or "scripts/eval_real_data/results_socket_taskA.json")
        measure(sample, out, sleep_s=args.sleep)
        return

    if args.mode == "taskC":
        # Task C 의 fixture 파일은 별도 스크립트에서 생성
        agentic_fx_path = ROOT / "scripts" / "eval_real_data" / "agentic_fixtures.json"
        if not agentic_fx_path.exists():
            print(f"ERROR: {agentic_fx_path} 없음. agentic dataset 큐레이션 먼저.")
            return
        fx = json.loads(agentic_fx_path.read_text(encoding="utf-8"))["fixtures"]
        out = Path(args.out or "scripts/eval_real_data/results_socket_taskC.json")
        measure(fx, out, sleep_s=args.sleep)
        return


if __name__ == "__main__":
    main()
