import unittest
from jockyx.lang import compile_source, JockyError

GOOD = '''RULE R-1 "x" ATTACK "T1059.001"
SCAN PROCESS WHERE parent = "powershell" AND unsigned = TRUE AND network = TRUE
REPORT severity HIGH'''


class Lang(unittest.TestCase):
    def test_compile_blueprint_example(self):
        ir = compile_source('SCAN PROCESS\nWHERE parent = "powershell"\nAND unsigned = TRUE\nAND network = TRUE\n\nREPORT severity HIGH')[0]
        self.assertEqual(ir["target"], "process")
        self.assertEqual(ir["query"]["op"], "and")
        self.assertIn("network_conn", ir["telemetry_requirements"])
        self.assertEqual(ir["action"]["severity"], "HIGH")

    def test_ir_deterministic(self):
        self.assertEqual(compile_source(GOOD)[0]["ir_hash"], compile_source(GOOD)[0]["ir_hash"])

    def test_precedence_and_not(self):
        q = compile_source('SCAN PROCESS WHERE NOT name = "a" OR pid > 5 AND user = "x" REPORT HIGH')[0]["query"]
        self.assertEqual(q["op"], "or")

    def test_errors(self):
        for src, frag in [
            ('SCAN PROCESS WHERE bogus = 1 REPORT HIGH', "unknown field"),
            ('SCAN PROCESS WHERE unsigned ~ "x" REPORT HIGH', "not valid"),
            ('SCAN PROCESS WHERE pid = "x" REPORT HIGH', "expects int"),
            ('SCAN NOPE REPORT HIGH', "unknown target"),
            ('SCAN PROCESS REPORT SEVERE', "invalid severity"),
            ('SCAN PROCESS WHERE name MATCHES "(" REPORT LOW', "invalid regex"),
            ('SCAN PROCESS WHERE name = REPORT LOW', "expected a value"),
            ('SCAN PROCESS WHERE name = "a" REPORT LOW\nSCAN PROCESS REPORT LOW ATTACK "X1"', "ATT&CK"),
        ]:
            with self.assertRaises(JockyError, msg=src) as cm:
                compile_source(src)
            self.assertIn(frag, str(cm.exception))

    def test_duplicate_ids(self):
        with self.assertRaises(JockyError):
            compile_source(GOOD + "\n" + GOOD)


if __name__ == "__main__":
    unittest.main()
