"""옵션 A (EXTEND + cluster) 의 시뮬레이션 재측정.

Task C 의 detected vocabulary 를 7 cluster 로 normalize.
시나리오 가정:
  정상 100 (counter-factual): 정직한 작성자 → declared = detected → CLEAN
  악성 34  (적대적):           작성자 거짓 → declared = empty → 모든 cluster = undeclared → SUSPICIOUS

비교: original Task C verdict vs EXTEND cluster diff verdict.
"""
from __future__ import annotations

import json
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# 7 Cluster 정의 (MITRE Tactic anchor)
# detected vocabulary → cluster
CLUSTER_OF_DETECTED = {
    "network": "C2-network",
    "llm-call": "C2-network",
    "mcp-client": "C2-network",
    "mcp-server": "agent-comm",
    "agent-to-agent": "agent-comm",
    "filesystem-read": "Discovery-fs",
    "filesystem-write": "Impact-fs",
    "shell": "Execution",
    "code-exec": "Execution",
    "dynamic-tool-load": "Execution",
    "env-secrets": "CredAccess",
    "credential-paths": "CredAccess",
    "memory-persistent": "Collection",
    "db-access": "Collection",
    "tool-loop": "agent-comm",  # agent loop = communication pattern
}

# 위험 cluster (의심 가산 대상)
DANGEROUS_CLUSTERS = {
    "C2-network", "Execution", "CredAccess",
    "Impact-fs", "Collection", "agent-comm",
}


def normalize_to_clusters(detected: list[str]) -> set[str]:
    """detected vocabulary list → cluster set."""
    return {CLUSTER_OF_DETECTED[d] for d in detected
            if d in CLUSTER_OF_DETECTED}


# ─────────────── 시나리오 ───────────────

def verdict_with_extend(item: dict, scenario: str) -> str:
    """EXTEND simulation verdict.

    scenario:
      "honest_author"    — declared = detected (counter-factual 정상)
      "adversarial"      — declared = {} (악성 적대적)
      "absent_manifest"  — 매니페스트 부재 (현재 상태)
    """
    detected = set(item.get("manifest_off", {}).get("detected", []))
    detected_clusters = normalize_to_clusters(list(detected))

    if scenario == "honest_author":
        declared = detected_clusters  # 모두 declared
    elif scenario == "adversarial":
        declared = set()  # 모두 미선언
    else:
        # absent_manifest → 우리 도구 original verdict 유지
        return item.get("manifest_off", {}).get("verdict", "CLEAN")

    undeclared = detected_clusters - declared
    dangerous_undeclared = undeclared & DANGEROUS_CLUSTERS

    # verdict 정책 (cluster diff 기반)
    if not detected_clusters:
        # detected 없으면 우리 도구 original 그대로 (작은 placeholder 등)
        return item.get("manifest_off", {}).get("verdict", "CLEAN")

    if not dangerous_undeclared:
        # 모든 위험 detected 가 declared → CLEAN
        return "CLEAN" if not item.get("is_agentic") else "AGENTIC"

    # 미선언 위험 있음
    if len(dangerous_undeclared) >= 3:
        return "MALICIOUS"  # 다수 미선언 = 강한 의심
    if len(dangerous_undeclared) >= 2:
        return "HIGH_RISK"
    return "SUSPICIOUS"


def measure(items: list[dict], label: str, dataset_name: str, scenario: str):
    print(f"\n=== {dataset_name} ({len(items)} 패키지, label={label}, scenario={scenario}) ===")
    is_caught = lambda v: v in ("MALICIOUS", "HIGH_RISK", "SUSPICIOUS")

    # original
    orig_caught = sum(1 for x in items
                      if is_caught(x.get("manifest_off", {}).get("verdict", "")))
    # EXTEND simulation
    new_verdicts = [verdict_with_extend(x, scenario) for x in items]
    new_caught = sum(1 for v in new_verdicts if is_caught(v))

    n = len(items)
    if label == "benign":
        print(f"  FPR original:  {orig_caught}/{n} = {orig_caught/n:.4f}")
        print(f"  FPR EXTEND:    {new_caught}/{n} = {new_caught/n:.4f}  (Δ {(new_caught-orig_caught)/n:+.4f})")
    else:
        print(f"  Recall original: {orig_caught}/{n} = {orig_caught/n:.4f}")
        print(f"  Recall EXTEND:   {new_caught}/{n} = {new_caught/n:.4f}  (Δ {(new_caught-orig_caught)/n:+.4f})")

    # verdict 분포
    orig_dist = Counter(x.get("manifest_off", {}).get("verdict", "") for x in items)
    new_dist = Counter(new_verdicts)
    print(f"  Original distribution: {dict(orig_dist)}")
    print(f"  EXTEND   distribution: {dict(new_dist)}")

    # 변화 샘플
    changes = []
    for x, nv in zip(items, new_verdicts):
        ov = x.get("manifest_off", {}).get("verdict", "")
        if ov != nv:
            changes.append((x["name"], ov, nv,
                            x.get("manifest_off",{}).get("detected",[])))
    print(f"  변경 ({len(changes)}건):")
    for name, ov, nv, det in changes[:15]:
        print(f"    {name:42s} {ov:11s} → {nv:11s} det={det[:3]}")
    if len(changes) > 15:
        print(f"    ... +{len(changes)-15}건")

    return {
        "scenario": scenario, "label": label, "n": n,
        "orig_caught": orig_caught, "new_caught": new_caught,
        "orig_rate": round(orig_caught/n, 4),
        "new_rate": round(new_caught/n, 4),
        "delta": round((new_caught-orig_caught)/n, 4),
        "orig_dist": dict(orig_dist),
        "new_dist": dict(new_dist),
        "changes_count": len(changes),
    }


def main():
    benign = json.loads(
        (ROOT / "scripts" / "eval_real_data" /
         "results_agentic_manifest_ablation.json").read_text(encoding="utf-8")
    )["fixtures"]
    benign_valid = [x for x in benign if "error" not in x]

    mal = json.loads(
        (ROOT / "scripts" / "eval_real_data" /
         "results_agentic_malicious_ablation.json").read_text(encoding="utf-8")
    )["fixtures"]
    mal_valid = [x for x in mal if "error" not in x]

    # 시나리오 1: 정직한 작성자 (정상 100)
    r_honest_benign = measure(benign_valid, "benign", "정상 agentic 100", "honest_author")
    # 시나리오 2: 적대적 작성자 (악성 34)
    r_adv_mal = measure(mal_valid, "malicious", "악성 agentic 34", "adversarial")
    # 비교: 적대적 작성자 (정상 100 — 매니페스트 없음/거짓 시 어떻게 보이나)
    r_adv_benign = measure(benign_valid, "benign", "정상 100 (적대적 가정)", "adversarial")
    # 정직한 작성자가 악성을 만들면? (악성도 정직 declare 한다면 → 안 잡힘 = 우리 도구 한계)
    r_honest_mal = measure(mal_valid, "malicious", "악성 34 (정직 가정 — 잡힘 X)", "honest_author")

    # 종합
    print(f"\n{'='*80}\n=== 종합 ===\n{'='*80}")
    print(f"매니페스트 EXTEND + cluster diff simulation:")
    print()
    print(f"  정상 100 (정직한 작성자):  FPR {r_honest_benign['orig_rate']} → {r_honest_benign['new_rate']}  ★ Δ {r_honest_benign['delta']:+.4f}")
    print(f"  악성 34  (적대적 작성자):  Recall {r_adv_mal['orig_rate']} → {r_adv_mal['new_rate']}  ★ Δ {r_adv_mal['delta']:+.4f}")
    print()
    print(f"  [참고] 정상 100 (적대적 가정): FPR {r_adv_benign['orig_rate']} → {r_adv_benign['new_rate']}")
    print(f"  [참고] 악성 34 (정직 가정):    Recall {r_honest_mal['orig_rate']} → {r_honest_mal['new_rate']}")

    out = {
        "policy": "EXTEND cluster diff simulation",
        "clusters": list(set(CLUSTER_OF_DETECTED.values())),
        "dangerous_clusters": sorted(DANGEROUS_CLUSTERS),
        "scenarios": {
            "honest_benign_100": r_honest_benign,
            "adversarial_malicious_34": r_adv_mal,
            "adversarial_benign_100": r_adv_benign,
            "honest_malicious_34": r_honest_mal,
        },
    }
    out_path = ROOT / "scripts" / "eval_real_data" / "results_extend_cluster_simulation.json"
    out_path.write_text(json.dumps(out, ensure_ascii=False, indent=2),
                        encoding="utf-8")
    print(f"\nsaved: {out_path}")


if __name__ == "__main__":
    main()
