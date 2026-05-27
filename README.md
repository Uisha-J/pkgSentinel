# pkgsentinel

> Supply-chain analysis tool for PyPI / npm packages.
> Flags AI-hallucinated (slopsquatting) and traditionally malicious packages
> through static analysis, multi-agent LLM review, and real-time monitoring.

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
![Python](https://img.shields.io/badge/python-3.11+-green.svg)
![Status](https://img.shields.io/badge/status-research%20preview-orange.svg)

---

## What it does

`pkgsentinel` analyzes a package on PyPI / npm **without installing it**, in
layered stages across the supply-chain attack surface:

| Layer | Role |
|---|---|
| **Layer 0** — registry / threat-intel | Encrypted DB lookup against 220k+ OSV/GHSA advisories + the OSSF malicious-packages list |
| **Layer 1** — source extraction + agentic gate | Memory-streamed archive analysis + Agentic classification for AI-agent packages |
| **Layer 2** — behavior sequence | 4-dimension API call extraction (Python AST + tree-sitter JS) |
| **Layer 3** — pattern matching | 49-entry malicious-indicator taxonomy (7 categories; 36 with active matchers) + sequence pattern mining + taint slicing + MITRE ATT&CK embedding match |
| **Layer 4** — LLM dual-check | Multi-agent verification (semantic / version-diff / dependency) with consensus voting |
| **Layer 5** — additional analysis | Recursive dependency, binary inspection, optional sandbox execution |
| **Layer 6** — verdict + standard outputs | CycloneDX 1.5 VEX, STIX 2.1 / TAXII 2.1, HMAC-signed webhooks, Falco rules + Tetragon TracingPolicy, SafeDep pmg policy |

Resulting verdict is one of: `MALICIOUS / HIGH_RISK / SUSPICIOUS / AGENTIC / CLEAN / ERROR / CANNOT_ANALYZE`.

---

## Why it exists

Existing supply-chain scanners (Trivy / Grype / OSV-Scanner) optimize for
known-CVE matching against version metadata. They miss two emerging threat
classes:

1. **Slopsquatting** — LLMs hallucinate non-existent package names; attackers
   pre-register those names with malicious payloads.
2. **Agentic packages** — LangChain / AutoGen / CrewAI-style libraries whose
   *legitimate behavior* (tool use, shell, code-exec) overlaps with malicious
   patterns, producing massive false positives in classical scanners.

`pkgsentinel` addresses both with new mechanisms:

- **Agentic Manifest** — a proposed *transparency standard* (this project) for
  agentic packages to declare their capability boundaries in `pyproject.toml` /
  `package.json`. The scanner cross-checks declared vs. detected capabilities to
  surface under-declaration. **It is a transparency aid, not a standalone
  security control**: the manifest is written by the package author, so an
  adaptive attacker can declare everything to avoid an under-declaration flag.
  Self-declared mitigations (`session_isolation`, design patterns) only reduce
  severity when corroborated by code signatures; unverified declarations are
  recorded but grant no exemption. Robust trust requires signed manifests
  (e.g. Sigstore) + external attestation, which is out of scope for v0.1.
- **Trust by Verification** — popular packages are not whitelisted; they run the
  same full pipeline and are prioritized in the scan queue (popularity rank
  raises urgency), since past supply-chain incidents (event-stream, ua-parser-js,
  XZ) all hit widely-used packages.
- **Encrypted threat DB** — SQLCipher AES-256. Cache integrity is sha256 by
  default; the Merkle-root and row-HMAC layers are opt-in (`paranoid` mode).
  The default mode therefore verifies one layer, not three.

---

## Quick start

### Install (editable)

```bash
git clone https://github.com/Uisha-J/pkgSentinel.git pkgsentinel
cd pkgsentinel
python -m venv .venv && source .venv/bin/activate    # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
```

### Initialize the encrypted DB

```bash
export AISLOP_DB_KEY="your-strong-passphrase"        # or write to ~/.pkgsentinel/db.key
python -m pkgsentinel.db.threat_db --init
python -m pkgsentinel.feeds.refresh --all            # ingests OSV / popular / IoC feeds
```

### Analyze a package (offline mode, no LLM cost)

```python
from pkgsentinel.pipeline import run_pipeline
from pkgsentinel.schema import Ecosystem

report = run_pipeline(
    package="requests",
    ecosystem=Ecosystem.PYPI,
    llm_mode="stub",            # 'claude' for paid LLM
    integrity_mode="strict",    # 'paranoid' adds Merkle + HMAC
)
print(report.verdict.value, len(report.evidence), "evidence items")
```

### Real-time monitoring (cron)

```cron
*/10 * * * *  python -m pkgsentinel.monitor.cron_main watch-pypi
*/5  * * * *  python -m pkgsentinel.monitor.cron_main watch-npm  --limit 200
*/5  * * * *  python -m pkgsentinel.monitor.cron_main worker     --max 5
0 3  * * *    python -m pkgsentinel.monitor.cron_main refresh-feeds
```

Detection signals are emitted to:
- `AISLOP_STIX_OUT_DIR/` — STIX 2.1 bundles
- `AISLOP_FALCO_OUT_DIR/` — Falco rule + Tetragon `TracingPolicy` YAML
- `AISLOP_WEBHOOK_URL` — HMAC-SHA256 signed POST

---

## Project status

Research preview. Verified by:

- **pytest suites** covering encrypted DB integrity, agentic classification,
  real-time pipeline, multi-stage verdict rules, and stage-level cache triggers.
  CI runs the unit suites only; the `eval_*` scripts and the LLM path are run
  manually (they need network / an `ANTHROPIC_API_KEY`).
- **120 synthetic fixtures** (`scripts/eval_synthetic.py`, cycle 11) —
  P=1.000 R=0.983 F1=0.992. **Caveat:** these fixtures are authored in-repo, so
  the score measures internal-pattern coverage, not generalization to unseen
  malware. Treat it as a regression signal, not a field accuracy claim.
- **550 real-data fixtures** (`scripts/eval_real.py` against
  [Datadog/malicious-software-packages-dataset][datadog-ds]) —
  overall P=0.96 R=0.73 F1=0.83;
  *compromised_lib subset (legit-package compromise, e.g. event-stream / xz)*
  P=1.000 R=0.944 [Wilson CI 0.85, 0.98]. The cached corpus is gitignored, so
  exact numbers require re-fetching the dataset.
- **100 stratified fixtures with Claude Sonnet 4.5 LLM** — F1 0.94, FP 13→2
  (requires an API key to reproduce).
  See [`docs/cost_model.md`](docs/cost_model.md) for token cost model.

Two demo scripts (`examples/synthetic_malicious_demo.py`,
`examples/indicator_47_demo.py`) are kept for human inspection but not part
of automated CI — equivalent regression is covered by `eval_synthetic.py`.

[datadog-ds]: https://github.com/DataDog/malicious-software-packages-dataset

---

## Documentation

- [`docs/architecture.md`](docs/architecture.md) — pipeline overview + operational topology
- [`docs/cost_model.md`](docs/cost_model.md) — Stage 5 LLM cost model (per-call
  tokens, daily/monthly scenarios, cache strategy)
- [`docs/agentic-manifest/`](docs/agentic-manifest/) — Agentic Manifest specification, decision
  tree, and R1-R4 rule catalogue
- [`examples/systemd/`](examples/systemd/) — systemd unit files for
  pkgsentinel-worker / pkgsentinel-cron deployment

---

## License

Apache License 2.0 — see [LICENSE](LICENSE).
