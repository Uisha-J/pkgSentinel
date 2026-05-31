"""PyPI 비교용 Bandit 측정 (malicious recall + benign FP). PyPI=Python → Bandit 공정 비교."""
import sys, json, subprocess, tempfile, zipfile, tarfile, os
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DATA = ROOT / "scripts" / "eval_real_data"


def extract(zp, td):
    try:
        if str(zp).endswith((".tar.gz", ".tgz")):
            with tarfile.open(zp) as t: t.extractall(td); return True
        with zipfile.ZipFile(zp) as z:
            try: z.setpassword(b"infected")
            except Exception: pass
            z.extractall(td)
        # zip 안에 sdist(tar.gz)가 또 있으면 풀기
        for r, _, fs in os.walk(td):
            for f in fs:
                if f.endswith((".tar.gz", ".tgz")):
                    try:
                        with tarfile.open(os.path.join(r, f)) as t: t.extractall(r)
                    except Exception: pass
        return True
    except Exception:
        return False


def bandit(td):
    try:
        r = subprocess.run(["bandit", "-r", str(td), "-f", "json", "-q"],
                           capture_output=True, text=True, timeout=30)
        if r.returncode > 1:
            return "ERROR", 0, 0
        out = json.loads(r.stdout) if r.stdout else {}
        hi = sum(1 for i in out.get("results", []) if (i.get("issue_severity") or "").upper() == "HIGH")
        med = sum(1 for i in out.get("results", []) if (i.get("issue_severity") or "").upper() == "MEDIUM")
        if hi >= 1: return "MALICIOUS", hi, med
        if med >= 1: return "SUSPICIOUS", hi, med
        return "CLEAN", hi, med
    except Exception:
        return "ERROR", 0, 0


def run(fix_file, label):
    fx = json.loads((DATA / fix_file).read_text(encoding="utf-8"))["fixtures"]
    caught = clean = err = 0
    is_mal = lambda v: v in ("MALICIOUS", "SUSPICIOUS")
    for i, item in enumerate(fx, 1):
        zp = DATA / item["archive_path"]
        if not zp.exists(): continue
        with tempfile.TemporaryDirectory() as td:
            if not extract(zp, td):
                err += 1; continue
            v, hi, med = bandit(Path(td))
        if i % 10 == 0:
            print(f"  [{label}] {i}/{len(fx)} (탐지 {caught})", flush=True)
        if v == "ERROR": err += 1
        elif is_mal(v): caught += 1
        else: clean += 1
    n = caught + clean
    print(f"[{label}] n={n} 탐지={caught} 미탐={clean} ERR={err}", flush=True)
    return caught, clean, err, n


print("=== Bandit on PyPI ===", flush=True)
m = run("pypi_malicious_fixtures.json", "malicious 80")
print(f"  malicious recall = {m[0]/max(1,m[3]):.3f}", flush=True)
b = run("benign_pypi_fixtures.json", "benign 59")
print(f"  benign FP = {b[0]}/{b[3]} = {b[0]/max(1,b[3]):.3f}", flush=True)
