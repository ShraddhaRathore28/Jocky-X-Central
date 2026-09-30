# Architecture

```
.jocky rule -> lexer/parser -> semantic check -> IR (JSON) --+
                                                             v
 Windows adapter | Ubuntu adapter | Replay adapter -> common Event schema
                                                             v
   features.py (process tree, ancestry, net/mem joins) -> executor.py (IR eval)
                                                             v
   scoring.py (explainable fusion, config/scoring.json) -> alerts
                                                             v
   timeline.py (Forensic Time Machine) + evidence.py (SHA-256 bundle)  -> SQLite store -> REST API -> dashboard
 CI lab (cicd.py): compile -> replay traces -> expected vs actual -> deploy/reject
```

| Blueprint module | Code |
|---|---|
| 1 Language & compiler | `jockyx/lang/` |
| 2 Cross-platform agent | `jockyx/adapters/`, `jockyx/agent.py`, `jockyx/events.py` |
| 3 Behavior detection | `jockyx/engine/features.py`, `executor.py`, `rules/*.jocky` |
| 4 Memory/driver analytics | `MEMORY_EVENT`/`DRIVER_EVENT` targets, `traces/generate.py` |
| 5 Timeline, evidence, CI/CD | `timeline.py`, `evidence.py`, `cicd.py`, `.github/workflows/ci.yml` |
| 6 Fusion, explainability, dashboard | `engine/scoring.py`, `server/` |

Design notes
- Scoring is additive and transparent: each point maps to a named indicator (weights in `config/scoring.json`). Final severity = max(rule severity, score band).
- Alert IDs are deterministic hashes, so re-ingesting the same telemetry is idempotent.
- The server is stdlib-only (no install needed); the dashboard is a single static page that escapes all event data.
- Ingest supports an optional shared token (`--token`); the server binds to localhost by default.
