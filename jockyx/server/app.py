"""Central management server (stdlib only). REST API + static dashboard."""
import json, os, re, threading, time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs
from ..engine import Engine
from ..events import Event
from ..lang import compile_source, JockyError
from ..store import Store
from ..timeline import build_timeline, time_machine
from ..evidence import build_bundle, render_report

STATIC = os.path.join(os.path.dirname(__file__), "static")


class JockyApp:
    def __init__(self, store=None, rules_ir=None, token=None):
        self.store, self.token, self.lock = store or Store(), token, threading.Lock()
        self.set_rules(rules_ir or [])

    def set_rules(self, rules_ir):
        self.rules_ir = rules_ir
        self.engine = Engine(rules_ir)

    def ingest(self, events, seen_at=None):
        with self.lock:
            self.store.add_events(events, seen_at)
            for ep in {e.endpoint_id for e in events}:
                self.store.replace_alerts(ep, self.engine.analyze(self.store.events(ep)))

    def summary(self):
        eps, alerts = self.store.endpoints(), self.store.alerts()
        sev = {s: sum(a["severity"] == s for a in alerts) for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW")}
        ci = self.store.last_ci() or {}
        return {"endpoints": {"windows": sum(e["os"] == "Windows" and e["online"] for e in eps),
                              "ubuntu": sum(e["os"] == "Ubuntu" and e["online"] for e in eps),
                              "offline": sum(not e["online"] for e in eps), "total": len(eps)},
                "alerts": sev, "rules_active": len(self.rules_ir), "tests_passing": ci.get("pass_rate"),
                "agents_online": sum(e["online"] for e in eps)}


def make_handler(app):
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a): pass

        def _send(self, code, body, ctype="application/json", extra=None):
            b = body if isinstance(body, bytes) else json.dumps(body).encode()
            self.send_response(code)
            self.send_header("Content-Type", ctype); self.send_header("Content-Length", str(len(b)))
            self.send_header("X-Content-Type-Options", "nosniff")
            for k, v in (extra or {}).items(): self.send_header(k, v)
            self.end_headers(); self.wfile.write(b)

        def _auth(self):
            if app.token and self.headers.get("X-JOCKY-Token") != app.token:
                self._send(401, {"error": "bad or missing X-JOCKY-Token"}); return False
            return True

        def do_GET(self):
            u = urlparse(self.path); q = {k: v[0] for k, v in parse_qs(u.query).items()}; p = u.path
            s = app.store
            if p in ("/", "/index.html"):
                with open(os.path.join(STATIC, "index.html"), "rb") as fh:
                    return self._send(200, fh.read(), "text/html; charset=utf-8")
            if not p.startswith("/api/"): return self._send(404, {"error": "not found"})
            if p == "/api/summary": return self._send(200, app.summary())
            if p == "/api/endpoints": return self._send(200, s.endpoints())
            if p == "/api/alerts": return self._send(200, s.alerts(q.get("severity"), q.get("endpoint"), q.get("q")))
            if p == "/api/rules": return self._send(200, s.rules())
            if p == "/api/ci": return self._send(200, s.last_ci() or {})
            m = re.fullmatch(r"/api/alerts/([\w\-]+)(?:/(timeline|bundle|report|context))?", p)
            if m:
                a = s.alert(m.group(1))
                if not a: return self._send(404, {"error": "unknown alert"})
                evs = s.events(a["endpoint_id"]); tl = build_timeline(a, evs); what = m.group(2)
                if what is None: return self._send(200, a)
                if what == "timeline": return self._send(200, tl)
                if what == "context":
                    return self._send(200, time_machine(evs, a["endpoint_id"], a["timestamp"], int(q.get("before", 60)), int(q.get("after", 60))))
                if what == "report":
                    return self._send(200, render_report(a, tl).encode(), "text/markdown; charset=utf-8",
                                      {"Content-Disposition": f'attachment; filename="{a["alert_id"]}.md"'})
                ir = next((r for r in app.rules_ir if r["rule_id"] == a["rule_id"]), {})
                return self._send(200, build_bundle(a, tl, evs, ir), "application/zip",
                                  {"Content-Disposition": f'attachment; filename="{a["alert_id"]}.zip"'})
            self._send(404, {"error": "not found"})

        def do_POST(self):
            n = int(self.headers.get("Content-Length", 0))
            if n > 20_000_000: return self._send(413, {"error": "payload too large"})
            try: body = json.loads(self.rfile.read(n) or b"{}")
            except ValueError: return self._send(400, {"error": "invalid JSON"})
            if self.path == "/api/rules/validate":          # rule editor: parse + check + compile (no deploy)
                try: return self._send(200, {"ok": True, "ir": compile_source(body.get("source", ""))})
                except JockyError as e: return self._send(200, {"ok": False, "errors": e.errors})
            if self.path == "/api/ingest":
                if not self._auth(): return
                try: evs = [Event.from_dict(e) for e in body["events"]]
                except (KeyError, TypeError) as e: return self._send(400, {"error": f"bad event payload: {e}"})
                app.ingest(evs)
                return self._send(200, {"ingested": len(evs)})
            self._send(404, {"error": "not found"})
    return H


def make_server(app, host="127.0.0.1", port=8000):
    return ThreadingHTTPServer((host, port), make_handler(app))
