"""`jocky` command line interface."""
import argparse, glob, json, os, sys
from .lang import compile_file, JockyError
from .demo import ROOT


def _load_rules(path):
    files = sorted(glob.glob(os.path.join(path, "*.jocky"))) if os.path.isdir(path) else [path]
    out = []
    for f in files: out += compile_file(f)
    return out


def main(argv=None):
    ap = argparse.ArgumentParser(prog="jocky", description="JOCKY-X forensic detection framework")
    sub = ap.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("compile", help="compile a .jocky file to IR JSON"); c.add_argument("file")
    r = sub.add_parser("run", help="run rules against a replay trace"); r.add_argument("trace")
    r.add_argument("--rules", default=os.path.join(ROOT, "rules"))
    ci = sub.add_parser("ci", help="run the detection regression lab (exit 1 on failure)")
    ci.add_argument("--rules", default=os.path.join(ROOT, "rules")); ci.add_argument("--traces", default=os.path.join(ROOT, "traces"))
    ci.add_argument("--deploy", default=os.path.join(ROOT, "build", "deployed_rules.json"))
    d = sub.add_parser("demo", help="CI + load synthetic traces + start dashboard")
    d.add_argument("--host", default="127.0.0.1"); d.add_argument("--port", type=int, default=8000)
    s = sub.add_parser("serve", help="start empty central server with deployed rules")
    s.add_argument("--host", default="127.0.0.1"); s.add_argument("--port", type=int, default=8000)
    s.add_argument("--db", default="jockyx.db"); s.add_argument("--token")
    s.add_argument("--rules", default=os.path.join(ROOT, "build", "deployed_rules.json"))
    a = sub.add_parser("agent", help="run the live read-only endpoint agent")
    a.add_argument("--server", required=True); a.add_argument("--endpoint-id"); a.add_argument("--interval", type=int, default=30)
    a.add_argument("--token"); a.add_argument("--once", action="store_true")
    n = ap.parse_args(argv)

    try:
        if n.cmd == "compile":
            print(json.dumps(compile_file(n.file), indent=2))
        elif n.cmd == "run":
            from .adapters import ReplayAdapter
            from .engine import Engine
            from .timeline import build_timeline
            ad = ReplayAdapter(n.trace); evs = ad.collect()
            for al in Engine(_load_rules(n.rules)).analyze(evs):
                print(f'\n[{al["severity"]}] {al["alert_id"]} {al["rule_id"]} on {al["endpoint_id"]}  score={al["score"]}/100')
                for b in al["score_breakdown"]: print(f'   +{b["points"]:<3} {b["label"]}: {b["detail"]}')
                print("   why:", al["explanation"])
                for t in build_timeline(al, evs): print(f'     {t["ts"][11:]}  {t["label"]}')
        elif n.cmd == "ci":
            from .cicd import run_ci
            rep = run_ci(n.rules, n.traces, n.deploy)
            for ck in rep["checks"]: print(f'  [{ck["status"].upper():4}] {ck["name"]}: {ck["detail"]}')
            print(f'\n{rep["passed"]}/{rep["total"]} checks | TP={rep["tp"]} FP={rep["fp"]} FN={rep["fn"]} | deployed={len(rep["deployed"])} rejected={rep["rejected"]}')
            return 0 if rep["ok"] else 1
        elif n.cmd in ("demo", "serve"):
            from .server import make_server
            if n.cmd == "demo":
                from .demo import build_demo_app
                app, rep = build_demo_app()
            else:
                from .server import JockyApp
                from .store import Store
                from .cicd import run_ci
                rep = run_ci(os.path.join(ROOT, "rules"), os.path.join(ROOT, "traces"), n.rules)   # gate: only passing rules deploy
                app = JockyApp(Store(n.db), rep["_deployed_ir"], n.token)
                app.store.set_rules(rep["rules"]); app.store.save_ci(rep)
            srv = make_server(app, n.host, n.port)
            print(f"JOCKY-X Central on http://{n.host}:{n.port}  (Ctrl+C to stop)")
            try: srv.serve_forever()
            except KeyboardInterrupt: pass
        elif n.cmd == "agent":
            from .agent import run_agent
            run_agent(n.server, n.endpoint_id, n.interval, n.token, n.once)
    except JockyError as e:
        print(f"JOCKY error:\n{e}", file=sys.stderr); return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
