import glob, json, os, unittest, urllib.request, threading, zipfile, io, hashlib
from jockyx.adapters import ReplayAdapter
from jockyx.cicd import run_ci
from jockyx.demo import ROOT, build_demo_app
from jockyx.engine import Engine
from jockyx.lang import compile_file
from jockyx.server import make_server
from jockyx.timeline import build_timeline
from jockyx.evidence import build_bundle

RULES, TRACES = os.path.join(ROOT, "rules"), os.path.join(ROOT, "traces")


def ir():
    out = []
    for f in sorted(glob.glob(RULES + "/*.jocky")): out += compile_file(f)
    return out


class Detection(unittest.TestCase):
    def test_every_trace_matches_expectation(self):
        eng = Engine(ir())
        for tf in glob.glob(TRACES + "/*.json"):
            ad = ReplayAdapter(tf)
            self.assertEqual(sorted({a["rule_id"] for a in eng.analyze(ad.collect())}), ad.meta["expect"]["rules"], tf)

    def test_score_matches_blueprint(self):
        ad = ReplayAdapter(os.path.join(TRACES, "win_powershell_chain.json"))
        a = next(x for x in Engine(ir()).analyze(ad.collect()) if x["rule_id"] == "JOCKY-RULE-017")
        self.assertEqual(a["score"], 87)
        self.assertEqual(sorted(b["points"] for b in a["score_breakdown"]), [18, 20, 24, 25])
        self.assertEqual(a["severity"], "HIGH")
        for k in ("alert_id", "timestamp", "endpoint_id", "os", "severity", "threat_class", "confidence_score",
                  "supporting_evidence", "timeline_refs", "rule_id", "explanation"):
            self.assertIn(k, a)

    def test_timeline_order_and_marker(self):
        ad = ReplayAdapter(os.path.join(TRACES, "win_powershell_chain.json")); evs = ad.collect()
        a = next(x for x in Engine(ir()).analyze(evs) if x["rule_id"] == "JOCKY-RULE-017")
        tl = build_timeline(a, evs)
        self.assertEqual([t["ts"] for t in tl], sorted(t["ts"] for t in tl))
        self.assertEqual(tl[-1]["kind"], "alert")
        self.assertIn("Process Created: explorer.exe", tl[0]["label"])

    def test_bundle_manifest_integrity(self):
        ad = ReplayAdapter(os.path.join(TRACES, "ubuntu_webshell.json")); evs = ad.collect()
        a = Engine(ir()).analyze(evs)[0]
        z = zipfile.ZipFile(io.BytesIO(build_bundle(a, build_timeline(a, evs), evs)))
        for line in z.read("MANIFEST.sha256").decode().splitlines():
            h, name = line.split("  ")
            self.assertEqual(hashlib.sha256(z.read(name)).hexdigest(), h)

    def test_ci_passes_and_rejects_bad_rule(self):
        self.assertTrue(run_ci(RULES, TRACES)["ok"])
        import tempfile
        with tempfile.TemporaryDirectory() as d:   # a noisy rule must be rejected by the regression lab
            with open(os.path.join(d, "x.jocky"), "w") as fh:
                fh.write('RULE NOISY "x"\nSCAN PROCESS WHERE pid > 0\nREPORT LOW')
            rep = run_ci(d, TRACES)
            self.assertFalse(rep["ok"]); self.assertIn("NOISY", rep["rejected"])


class Server(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app, _ = build_demo_app(token="secret")
        cls.srv = make_server(cls.app, "127.0.0.1", 0)
        cls.base = f"http://127.0.0.1:{cls.srv.server_address[1]}"
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls): cls.srv.shutdown()

    def get(self, p): return json.load(urllib.request.urlopen(self.base + p))

    def test_api(self):
        s = self.get("/api/summary")
        self.assertEqual(s["endpoints"]["offline"], 1); self.assertEqual(s["tests_passing"], 100)
        alerts = self.get("/api/alerts"); self.assertGreater(len(alerts), 8)
        aid = alerts[0]["alert_id"]
        self.assertTrue(self.get(f"/api/alerts/{aid}/timeline"))
        self.assertIn(b"Investigation Report", urllib.request.urlopen(f"{self.base}/api/alerts/{aid}/report").read())
        self.assertTrue(urllib.request.urlopen(f"{self.base}/api/alerts/{aid}/bundle").read().startswith(b"PK"))
        self.assertIn(b"JOCKY", urllib.request.urlopen(self.base + "/").read())

    def test_validate_endpoint(self):
        def post(src):
            r = urllib.request.Request(self.base + "/api/rules/validate", json.dumps({"source": src}).encode())
            return json.load(urllib.request.urlopen(r))
        self.assertTrue(post('SCAN PROCESS WHERE name = "a" REPORT LOW')["ok"])
        self.assertFalse(post("garbage")["ok"])

    def test_ingest_requires_token(self):
        body = json.dumps({"events": []}).encode()
        with self.assertRaises(urllib.error.HTTPError) as cm:
            urllib.request.urlopen(urllib.request.Request(self.base + "/api/ingest", body))
        self.assertEqual(cm.exception.code, 401)
        ok = urllib.request.Request(self.base + "/api/ingest", body, {"X-JOCKY-Token": "secret"})
        self.assertEqual(json.load(urllib.request.urlopen(ok))["ingested"], 0)


class LiveLinux(unittest.TestCase):
    @unittest.skipUnless(os.name == "posix" and os.path.exists("/proc"), "Linux only")
    def test_ubuntu_adapter_schema(self):
        try: import psutil  # noqa
        except ImportError: self.skipTest("psutil missing")
        from jockyx.adapters.ubuntu import UbuntuAdapter
        evs = UbuntuAdapter("T").collect({"process_create"})
        self.assertTrue(evs and all(e.kind == "process_create" and e.os == "Ubuntu" for e in evs))


if __name__ == "__main__":
    unittest.main()
