"""Load rules + replay traces into an app (used by `jocky demo` and tests)."""
import glob, os, time
from .adapters import ReplayAdapter
from .cicd import run_ci
from .server.app import JockyApp
from .store import Store

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OFFLINE_DEMO = {"WIN-06"}   # shown as offline on the dashboard


def build_demo_app(db=":memory:", token=None, root=ROOT):
    rules, traces = os.path.join(root, "rules"), os.path.join(root, "traces")
    report = run_ci(rules, traces, os.path.join(root, "build", "deployed_rules.json"))
    app = JockyApp(Store(db), report["_deployed_ir"], token)
    app.store.set_rules(report["rules"]); app.store.save_ci(report)
    for tf in sorted(glob.glob(os.path.join(traces, "*.json"))):
        ad = ReplayAdapter(tf)
        seen = time.time() - (3600 if ad.endpoint_id in OFFLINE_DEMO else 0)
        app.ingest(ad.collect(), seen_at=seen)
    return app, report
