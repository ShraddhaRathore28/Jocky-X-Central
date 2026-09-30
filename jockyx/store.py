"""SQLite evidence/alert store."""
import json, sqlite3, threading, time
from .events import Event

SCHEMA = """
CREATE TABLE IF NOT EXISTS endpoints(endpoint_id TEXT PRIMARY KEY, os TEXT, first_seen REAL, last_seen REAL);
CREATE TABLE IF NOT EXISTS events(endpoint_id TEXT, event_id TEXT, ts TEXT, kind TEXT, json TEXT, PRIMARY KEY(endpoint_id,event_id));
CREATE TABLE IF NOT EXISTS alerts(alert_id TEXT PRIMARY KEY, endpoint_id TEXT, rule_id TEXT, severity TEXT, score INTEGER, ts TEXT, json TEXT);
CREATE TABLE IF NOT EXISTS rules(rule_id TEXT PRIMARY KEY, status TEXT, json TEXT);
CREATE TABLE IF NOT EXISTS ci_runs(id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL, json TEXT);
"""


class Store:
    def __init__(self, path=":memory:"):
        self.db = sqlite3.connect(path, check_same_thread=False)
        self.db.row_factory = sqlite3.Row
        self.lock = threading.RLock()
        self.db.executescript(SCHEMA)

    def add_events(self, events, seen_at=None):
        with self.lock:
            for e in events:
                self.db.execute("INSERT OR IGNORE INTO events VALUES(?,?,?,?,?)",
                                (e.endpoint_id, e.event_id, e.ts, e.kind, json.dumps(e.to_dict())))
                self.db.execute("INSERT OR IGNORE INTO endpoints VALUES(?,?,?,?)", (e.endpoint_id, e.os, time.time(), time.time()))
            for ep in {e.endpoint_id for e in events}:
                self.db.execute("UPDATE endpoints SET last_seen=? WHERE endpoint_id=?", (seen_at or time.time(), ep))
            self.db.commit()

    def events(self, endpoint_id=None):
        q, a = "SELECT json FROM events", ()
        if endpoint_id: q, a = q + " WHERE endpoint_id=?", (endpoint_id,)
        with self.lock:
            return [Event.from_dict(json.loads(r[0])) for r in self.db.execute(q + " ORDER BY ts", a)]

    def replace_alerts(self, endpoint_id, alerts):
        with self.lock:
            self.db.execute("DELETE FROM alerts WHERE endpoint_id=?", (endpoint_id,))
            for a in alerts:
                self.db.execute("INSERT OR REPLACE INTO alerts VALUES(?,?,?,?,?,?,?)",
                                (a["alert_id"], a["endpoint_id"], a["rule_id"], a["severity"], a["score"], a["timestamp"], json.dumps(a)))
            self.db.commit()

    def alerts(self, severity=None, endpoint=None, q=None):
        with self.lock:
            rows = [json.loads(r[0]) for r in self.db.execute("SELECT json FROM alerts ORDER BY ts DESC, score DESC")]
        if severity: rows = [a for a in rows if a["severity"] == severity.upper()]
        if endpoint: rows = [a for a in rows if a["endpoint_id"] == endpoint]
        if q:
            ql = q.lower(); rows = [a for a in rows if ql in json.dumps(a).lower()]
        return rows

    def alert(self, alert_id):
        with self.lock:
            r = self.db.execute("SELECT json FROM alerts WHERE alert_id=?", (alert_id,)).fetchone()
        return json.loads(r[0]) if r else None

    def endpoints(self, offline_after=120):
        with self.lock:
            rows = [dict(r) for r in self.db.execute("SELECT * FROM endpoints ORDER BY endpoint_id")]
        now = time.time()
        for r in rows:
            r["online"] = now - r["last_seen"] <= offline_after
            r["alerts"] = len(self.alerts(endpoint=r["endpoint_id"]))
        return rows

    def set_rules(self, rules_report):
        with self.lock:
            self.db.execute("DELETE FROM rules")
            for r in rules_report:
                self.db.execute("INSERT INTO rules VALUES(?,?,?)", (r["rule_id"], r["status"], json.dumps(r)))
            self.db.commit()

    def rules(self):
        with self.lock: return [json.loads(r[0]) for r in self.db.execute("SELECT json FROM rules ORDER BY rule_id")]

    def save_ci(self, report):
        rep = {k: v for k, v in report.items() if not k.startswith("_")}
        with self.lock:
            self.db.execute("INSERT INTO ci_runs(ts,json) VALUES(?,?)", (time.time(), json.dumps(rep))); self.db.commit()

    def last_ci(self):
        with self.lock:
            r = self.db.execute("SELECT json FROM ci_runs ORDER BY id DESC LIMIT 1").fetchone()
        return json.loads(r[0]) if r else None
