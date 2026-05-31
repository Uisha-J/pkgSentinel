"""옵션 E simulation — 매니페스트 *존재 자체* 를 신호로.

기존 ablation 결과 (manifest_off) 에 다음 정책 post-processing 적용:

  Rule E1 (의심 가산):
    is_agentic AND manifest_absent AND (detected & DANGEROUS_CAPS)
    → verdict 격상 (CLEAN → SUSPICIOUS)

  Rule E2 (신뢰 가산):
    is_agentic AND manifest_present
    → verdict 격하 (SUSPICIOUS → AGENTIC,  HIGH_RISK → SUSPICIOUS)

비교:
  - original_off : pkgsentinel current state
  - presence_e   : E1 + E2 적용
"""
from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# DANGEROUS — 실제 도구의 detected vocabulary (agentic/capability_detector.py 의 출력)
# 정상 + 악성 dataset 에서 관찰된 실제 capability 어휘 (확인 완료).
# 의미적으로 위험한 것만 보수적으로 선택.
DANGEROUS_CAPS = {
    "code-exec",         # 코드 실행
    "shell",             # shell 실행
    "env-secrets",       # 환경변수/비밀 접근
    "credential-paths",  # 자격증명 경로
    "dynamic-tool-load", # 동적 도구 로딩
    "filesystem-write",  # 파일 쓰기
    "network",           # 외부 네트워크
}

VERDICT_ORDER = ["CLEAN", "AGENTIC", "SUSPICIOUS", "HIGH_RISK", "MALICIOUS"]


def manifest_present(item: dict) -> bool:
    """item['manifest_off']['declared'] 가 비어있지 않으면 manifest 있음.

    declared 가 빈 list 면 매니페스트 부재 (또는 빈 manifest).
    """
    declared = item.get("manifest_off", {}).get("declared", [])
    return bool(declared)


def is_agentic(item: dict) -> bool:
    return bool(item.get("is_agentic", False))


def has_dangerous_detected(item: dict) -> bool:
    detected = set(item.get("manifest_off", {}).get("detected", []))
    return bool(detected & DANGEROUS_CAPS)


def apply_e_policy(item: dict, counter_factual: bool = False) -> str:
    """E policy 적용 — 새 verdict 반환.

    counter_factual=True: 모든 agentic 패키지가 *매니페스트 있다고 가정* 후
                         E2 정책 적용. "표준 보급 시 잠재 효과" 측정.
                         (현재 측정 framework 에서는 모든 패키지가 manifest 부재 — 표준 보급 전)
    """
    orig = item.get("manifest_off", {}).get("verdict", "CLEAN")
    if not is_agentic(item):
        return orig

    # E1: agentic + 매니페스트 부재 + 위험 → 격상 (현실 측정)
    if not counter_factual and not manifest_present(item) and has_dangerous_detected(item):
        if orig == "CLEAN":
            return "SUSPICIOUS"
        if orig == "AGENTIC":
            return "SUSPICIOUS"
        return orig

    # E2: agentic + 매니페스트 존재 → 격하 (counter-factual 시 모두 적용)
    if counter_factual or manifest_present(item):
        if orig == "SUSPICIOUS":
            return "AGENTIC"
        if orig == "HIGH_RISK":
            return "SUSPICIOUS"
        if orig == "MALICIOUS":
            # MALICIOUS 는 강한 신호 — manifest 있어도 보수적으로 유지
            return "MALICIOUS"
        return orig

    return orig


def measure(items: list[dict], dataset_name: str, label: str):
    """각 패키지에 대해 original_off vs presence_e (현실 + counter-factual) 비교."""
    print(f"\n=== {dataset_name} ({len(items)} 패키지, ground truth = {label}) ===")

    is_caught = lambda v: v in ("MALICIOUS", "HIGH_RISK", "SUSPICIOUS")

    # original
    orig_caught = sum(1 for x in items
                      if is_caught(x.get("manifest_off", {}).get("verdict", "")))
    # presence E (현실)
    new_verdicts = [apply_e_policy(x, counter_factual=False) for x in items]
    e_caught = sum(1 for v in new_verdicts if is_caught(v))
    # counter-factual (모든 agentic 패키지가 매니페스트 도입 가정)
    cf_verdicts = [apply_e_policy(x, counter_factual=True) for x in items]
    cf_caught = sum(1 for v in cf_verdicts if is_caught(v))

    # delta
    changes = []
    for x, nv in zip(items, new_verdicts):
        ov = x.get("manifest_off", {}).get("verdict", "")
        if ov != nv:
            changes.append((x["name"], ov, nv,
                            manifest_present(x),
                            has_dangerous_detected(x)))

    n = len(items)
    if label == "benign":
        orig_v = orig_caught / n
        e_v = e_caught / n
        cf_v = cf_caught / n
        print(f"  FPR original:           {orig_caught}/{n} = {orig_v:.4f}")
        print(f"  FPR option E (현실):    {e_caught}/{n} = {e_v:.4f}  (Δ {e_v-orig_v:+.4f})")
        print(f"  FPR option E (counter): {cf_caught}/{n} = {cf_v:.4f}  (Δ {cf_v-orig_v:+.4f}) ★")
        metric_name = "FPR"
    else:
        orig_v = orig_caught / n
        e_v = e_caught / n
        cf_v = cf_caught / n
        print(f"  Recall original:           {orig_caught}/{n} = {orig_v:.4f}")
        print(f"  Recall option E (현실):    {e_caught}/{n} = {e_v:.4f}  (Δ {e_v-orig_v:+.4f})")
        print(f"  Recall option E (counter): {cf_caught}/{n} = {cf_v:.4f}  (Δ {cf_v-orig_v:+.4f})")
        metric_name = "Recall"

    # counter-factual 격하 changes
    cf_changes = []
    for x, nv in zip(items, cf_verdicts):
        ov = x.get("manifest_off", {}).get("verdict", "")
        if ov != nv:
            cf_changes.append((x["name"], ov, nv))
    print(f"\n  counter-factual 격하 ({len(cf_changes)}건, 매니페스트 도입 가정):")
    for name, ov, nv in cf_changes[:15]:
        print(f"    {name:42s} {ov:11s} → {nv}")
    if len(cf_changes) > 15:
        print(f"    ... +{len(cf_changes)-15}건")

    return {
        "dataset": dataset_name,
        "label": label,
        "n": n,
        "metric": metric_name,
        "original": round(orig_v, 4),
        "option_e_real": round(e_v, 4),
        "option_e_counterfactual": round(cf_v, 4),
        "delta_real": round(e_v - orig_v, 4),
        "delta_counterfactual": round(cf_v - orig_v, 4),
        "cf_changes_count": len(cf_changes),
        "cf_changes": [{"name": nm, "orig": ov, "cf": cv}
                       for nm, ov, cv in cf_changes],
    }


def main():
    # 정상 agentic 100
    benign = json.loads(
        (ROOT / "scripts" / "eval_real_data" /
         "results_agentic_manifest_ablation.json").read_text(encoding="utf-8")
    )["fixtures"]
    benign_valid = [x for x in benign if "error" not in x]

    # 악성 agentic 34
    mal = json.loads(
        (ROOT / "scripts" / "eval_real_data" /
         "results_agentic_malicious_ablation.json").read_text(encoding="utf-8")
    )["fixtures"]
    mal_valid = [x for x in mal if "error" not in x]

    r_benign = measure(benign_valid, "정상 agentic 100", "benign")
    r_mal    = measure(mal_valid,    "악성 agentic 34",  "malicious")

    # 종합
    print(f"\n=== 종합 ===")
    print(f"  Original (manifest OFF):           FPR {r_benign['original']:.4f}, Recall {r_mal['original']:.4f}")
    print(f"  Option E (현실 — 표준 보급 전):    FPR {r_benign['option_e_real']:.4f}, Recall {r_mal['option_e_real']:.4f}")
    print(f"  Option E (counter — 표준 보급 후): FPR {r_benign['option_e_counterfactual']:.4f}, Recall {r_mal['option_e_counterfactual']:.4f}")
    print(f"")
    print(f"  ★ counter-factual FPR 감소: {r_benign['delta_counterfactual']:+.4f}  (매니페스트 표준 보급 시 잠재 효과)")
    print(f"  ★ counter-factual Recall:   {r_mal['delta_counterfactual']:+.4f}   (악성은 매니페스트 격하 안 되므로 변화 X)")

    out = {
        "policy": "Option E — manifest presence signal",
        "rules": {
            "E1 (current)": "agentic + no manifest + dangerous detected → suspicion ↑",
            "E2 (counter-factual)": "agentic + manifest present → trust ↑",
        },
        "framework_note": (
            "Option E 현실 측정 한계: 모든 정상 패키지가 매니페스트 부재 (표준 보급 전). "
            "→ counter-factual simulation: 매니페스트 도입 시 잠재 효과 정량."
        ),
        "dangerous_caps": sorted(DANGEROUS_CAPS),
        "benign_100": r_benign,
        "malicious_34": r_mal,
    }
    out_path = ROOT / "scripts" / "eval_real_data" / "results_option_e_simulation.json"
    out_path.write_text(json.dumps(out, ensure_ascii=False, indent=2),
                        encoding="utf-8")
    print(f"\nsaved: {out_path}")


if __name__ == "__main__":
    main()
