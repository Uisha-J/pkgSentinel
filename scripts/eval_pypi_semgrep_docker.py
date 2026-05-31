"""PyPI Semgrep (Docker) — 배치 스캔 (80개 한번에=OOM이라 8개씩).

verdict: ERROR severity >=1 finding 가진 패키지 = flagged (Bandit HIGH 동급 정책).
"""
import json, zipfile, tarfile, os, shutil, subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DATA = ROOT / "scripts" / "eval_real_data"
WORK = DATA / "_sg_work"
BATCH = 8
WINBASE = "C:/Users/08121/Desktop/test/Ai_Slopsquatting/pkgsentinel/scripts/eval_real_data/_sg_work"


def extract(zp, dest):
    try:
        with zipfile.ZipFile(zp) as z:
            try: z.setpassword(b"infected")
            except Exception: pass
            z.extractall(dest)
        return True
    except Exception:
        try:
            with tarfile.open(zp) as t: t.extractall(dest); return True
        except Exception:
            return False


def scan_batch(items_idx):
    """items_idx: [(pkgkey, zip_path)] -> flagged keys set."""
    if WORK.exists(): shutil.rmtree(WORK)
    WORK.mkdir(parents=True)
    keys = []
    for key, zp in items_idx:
        d = WORK / key
        d.mkdir()
        if extract(zp, d): keys.append(key)
    cmd = ["docker", "run", "--rm", "-v", f"{WINBASE}:/src", "semgrep/semgrep:latest",
           "semgrep", "scan", "--config", "p/python", "--config", "p/security-audit",
           "--json", "--quiet", "--metrics", "off", "/src"]
    r = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8",
                       errors="replace", timeout=900)
    flagged = set()
    try:
        out = json.loads(r.stdout)
        for f in out.get("results", []):
            sev = (f.get("extra", {}).get("severity") or "").upper()
            if sev not in ("ERROR","WARNING"):
                continue
            for p in f.get("path", "").split("/"):
                if p.startswith("p") and p[1:].isdigit():
                    flagged.add(p); break
    except Exception:
        print(f"    batch parse fail rc={r.returncode}", flush=True)
    shutil.rmtree(WORK, ignore_errors=True)
    return flagged


def measure(fix_file, label):
    fx = json.loads((DATA / fix_file).read_text(encoding="utf-8"))["fixtures"]
    pkgs = []
    for i, item in enumerate(fx):
        zp = DATA / item["archive_path"]
        if zp.exists():
            pkgs.append((f"p{i:03d}", zp))
    flagged_total = 0
    for b in range(0, len(pkgs), BATCH):
        batch = pkgs[b:b + BATCH]
        fl = scan_batch(batch)
        flagged_total += len(fl)
        print(f"  [{label}] {min(b+BATCH,len(pkgs))}/{len(pkgs)} (flagged누적 {flagged_total})", flush=True)
    n = len(pkgs)
    print(f"[{label}] n={n} flagged(ERROR/WARN>=1)={flagged_total} = {flagged_total/max(1,n):.3f}", flush=True)
    return flagged_total, n


print("=== Semgrep (Docker, batched) on PyPI ===", flush=True)
fm, nm = measure("pypi_malicious_fixtures.json", "malicious")
fb, nb = measure("benign_pypi_fixtures.json", "benign")
prec = fm / (fm + fb) if fm + fb else 0
print(f"\nSemgrep PyPI: recall={fm/max(1,nm):.3f}  benign_FP={fb}/{nb}={fb/max(1,nb):.3f}  precision={prec:.3f}", flush=True)
json.dump({"recall": round(fm/max(1,nm),3), "mal_caught": fm, "mal_n": nm,
           "benign_fp": fb, "benign_n": nb, "precision": round(prec,3)},
          open(DATA / "results_pypi_semgrep.json", "w"), indent=2)
print("saved.", flush=True)
