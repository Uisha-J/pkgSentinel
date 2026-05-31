"""TrapDoor 미탐 패키지가 실제 악성 페이로드를 가졌는지 객관 분류.

페이로드 없음(NO-CODE / BENIGN) = 탐지 대상 아님 → 제외 가능
악성 지표 있음 = 진짜 미탐(FN) → 유지
"""
import json, zipfile, tempfile, os, glob, re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DATA = ROOT / "scripts" / "eval_real_data"

d = json.loads((DATA / "results_incidents_pkg.json").read_text(encoding="utf-8"))
fx = d.get("fixtures", d.get("results", []))
miss = [x for x in fx
        if (x.get("incident_key") == "trapdoor" or x.get("source") == "datadog/trapdoor")
        and x.get("verdict") not in ("MALICIOUS", "HIGH_RISK", "SUSPICIOUS")]

IND = [
    ("exec", re.compile(r"\beval\(|child_process|execSync|spawnSync|require\(['\"]child")),
    ("net", re.compile(r"https?://[^\s'\"]+|fetch\(|axios|XMLHttpRequest|\.post\(|net\.connect|dns\.")),
    ("env", re.compile(r"process\.env|os\.homedir|\.npmrc|\.aws|id_rsa|privateKey|PRIVATE_KEY")),
    ("obf", re.compile(r"base64|atob\(|fromCharCode|_0x[0-9a-f]{4}|\\\\x[0-9a-f]{2}")),
    ("wallet", re.compile(r"clipboard|0x[a-fA-F0-9]{40}|mnemonic|seedphrase|seed phrase", re.I)),
    ("postinstall_remote", re.compile(r"postinstall[^\n]{0,80}(curl|wget|node -e|https?://)")),
]


def scan(zp):
    td = tempfile.mkdtemp()
    try:
        with zipfile.ZipFile(zp) as z:
            z.setpassword(b"infected"); z.extractall(td)
    except Exception:
        return "ZIPERR", ""
    code = ""
    pkgjson_scripts = ""
    for r, _, fs in os.walk(td):
        for f in fs:
            pth = os.path.join(r, f)
            if f.endswith((".js", ".ts", ".mjs", ".cjs")):
                try:
                    code += open(pth, encoding="utf-8", errors="replace").read() + "\n"
                except Exception:
                    pass
            elif f == "package.json":
                try:
                    pj = json.load(open(pth, encoding="utf-8", errors="replace"))
                    pkgjson_scripts = json.dumps(pj.get("scripts", {}))
                except Exception:
                    pass
    blob = code + " " + pkgjson_scripts
    if not code.strip():
        # 코드 없음 — package.json scripts 에 원격 호출 있나
        if re.search(r"curl|wget|node -e|https?://", pkgjson_scripts):
            return "HOOK-REMOTE", pkgjson_scripts[:80]
        return "NO-CODE", ""
    hits = [n for n, p in IND if p.search(blob)]
    return (",".join(hits) if hits else "BENIGN(지표0)"), ""


def find_zip(name):
    base = name.split("/")[-1]
    for g in glob.glob(str(DATA / "cache" / "incidents" / "trapdoor" / "*.zip")):
        if base.lower() in os.path.basename(g).lower():
            return g
    return None


print(f"TrapDoor 미탐 {len(miss)}개 분류:\n")
keep, drop = [], []
for m in miss:
    zp = find_zip(m["name"])
    res, ev = scan(zp) if zp else ("NOFILE", "")
    payload = res not in ("NO-CODE", "BENIGN(지표0)", "ZIPERR", "NOFILE", "HOOK-REMOTE") \
        or res == "HOOK-REMOTE"
    tag = "FN유지" if payload else "제외"
    (keep if payload else drop).append(m["name"])
    print(f"  [{tag}] {m['name'][:38]:38s} js={m.get('n_js')} -> {res} {ev}")

print(f"\n=== 분류 결과 ===")
print(f"  악성 페이로드 有 (진짜 FN, 유지): {len(keep)}")
print(f"  페이로드 無 (제외 대상):        {len(drop)}")
print("  제외:", drop)
(DATA / "trapdoor_miss_class.json").write_text(
    json.dumps({"keep_fn": keep, "drop_nopayload": drop}, ensure_ascii=False, indent=2),
    encoding="utf-8")
