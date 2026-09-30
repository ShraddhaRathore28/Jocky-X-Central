# JOCKY-X — Cross-Platform Forensic Detection & Investigation Language
**SIH 2026 · Problem Statement SIH26148 · NTRO**

`JOCKY Script → Compiler → Cross-Platform IR → OS Adapter → Detection → Evidence → Timeline → Dashboard`

JOCKY-X lets an investigator write one small forensic rule, compile it to a platform-independent IR, and run it on
Windows and Ubuntu through read-only adapters, with explainable scoring, an incident timeline, tamper-evident evidence
bundles, a CI/CD detection lab, and a central multi-endpoint dashboard. Defensive only — see [docs/SAFETY.md](docs/SAFETY.md).

```
SCAN PROCESS
WHERE parent = "powershell" AND unsigned = TRUE AND network = TRUE
REPORT severity HIGH
```

## Quick start (zero dependencies for the demo)
```bash
git clone <your-repo-url> && cd jocky-x
python -m jockyx demo            # runs CI lab, loads synthetic traces, serves http://127.0.0.1:8000
```
Open the dashboard: alerts, click one → score breakdown, "why", ATT&CK refs, timeline, report/bundle export.

```bash
pip install -e ".[dev]"          # optional: live agent (psutil) + pytest
python -m pytest -q              # 14 tests
python -m jockyx ci              # detection regression lab (exit 1 on regressions)
python -m jockyx compile rules/windows_execution_chains.jocky   # view the IR
python -m jockyx run traces/win_powershell_chain.json           # CLI investigation w/ timeline
```

### Multi-endpoint live mode
```bash
python -m jockyx serve --port 8000 --token S3CRET                      # central server (runs CI gate first)
pip install psutil
python -m jockyx agent --server http://<server>:8000 --token S3CRET --endpoint-id WIN-04   # on each endpoint
```
The same agent command works on Windows and Ubuntu; it picks the right adapter and only collects the telemetry kinds the deployed rules require.

## Explainable score (reproduces the blueprint example)
`win_powershell_chain` → **87/100** = ancestry +25, unsigned +20, abnormal network +18, memory +24 → **HIGH**. Weights: `config/scoring.json`.

## CI/CD detection lab
Every rule is compiled, replayed against benign + synthetic traces, and compared with expected detections
(`meta.expect` in each trace). Missed detections, false positives, or rules no trace exercises are **rejected**;
only passing rules are written to `build/deployed_rules.json`. GitHub Actions runs this on Ubuntu and Windows.

## Layout
`jockyx/lang` language & IR · `jockyx/adapters` Windows/Ubuntu/Replay · `jockyx/engine` features, executor, scoring ·
`jockyx/timeline.py` · `jockyx/evidence.py` · `jockyx/cicd.py` · `jockyx/server` API+dashboard · `rules/` · `traces/` · `tests/` · `docs/`

## Honest limitations
- Live Ubuntu collection is tested; the Windows adapter follows documented APIs but should be validated on a Windows host (CI runs the unit tests there).
- Live memory indicators exist for Linux only (`/proc/<pid>/maps` anonymous rwx regions, JIT runtimes allow-listed); on Windows memory events come from replayed/EDR-normalized telemetry.
- Ubuntu "signed" is a package-path heuristic, not a cryptographic check. Process-tree correlation ignores PID reuse.
- Scoring is rule-based; an ML-assisted scorer (scikit-learn) and SHAP views from the blueprint are future work.
