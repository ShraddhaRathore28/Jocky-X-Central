"""CI/CD Detection Laboratory: compile -> replay traces -> compare expected vs actual -> deploy or reject."""
import glob, json, os
from .lang import compile_file, JockyError
from .engine import Engine
from .adapters import ReplayAdapter


def run_ci(rules_dir, traces_dir, deploy_path=None):
    checks, compiled, rule_src = [], [], {}
    for f in sorted(glob.glob(os.path.join(rules_dir, "*.jocky"))):
        try:
            irs = compile_file(f)
            compiled += irs
            for r in irs: rule_src[r["rule_id"]] = os.path.basename(f)
            checks.append({"name": f"compile {os.path.basename(f)}", "status": "pass", "detail": f"{len(irs)} rule(s)"})
        except JockyError as e:
            checks.append({"name": f"compile {os.path.basename(f)}", "status": "fail", "detail": str(e)})
    ids = [r["rule_id"] for r in compiled]
    dup = {i for i in ids if ids.count(i) > 1}
    if dup: checks.append({"name": "unique rule ids", "status": "fail", "detail": ", ".join(sorted(dup))})

    engine, rule_fail, fired_any = Engine(compiled), {i: [] for i in ids}, set()
    tp = fp = fn = 0
    for tf in sorted(glob.glob(os.path.join(traces_dir, "*.json"))):
        ad = ReplayAdapter(tf)
        exp = set(ad.meta.get("expect", {}).get("rules", []))
        got = {a["rule_id"] for a in engine.analyze(ad.collect())}
        fired_any |= got
        miss, extra = exp - got, got - exp
        tp += len(exp & got); fn += len(miss); fp += len(extra)
        for r in miss: rule_fail.setdefault(r, []).append(f"missed on {ad.meta['name']}")
        for r in extra: rule_fail.setdefault(r, []).append(f"false positive on {ad.meta['name']}")
        ok = not miss and not extra
        checks.append({"name": f"trace {ad.meta['name']}", "status": "pass" if ok else "fail",
                       "detail": "expected == actual" if ok else f"missing={sorted(miss)} unexpected={sorted(extra)}"})
    for r in ids:
        if r not in fired_any:
            rule_fail[r].append("no positive trace exercises this rule")
            checks.append({"name": f"coverage {r}", "status": "fail", "detail": "rule never fires in any trace"})
    rules = [{"rule_id": r["rule_id"], "name": r["name"], "severity": r["action"]["severity"], "target": r["target"],
              "file": rule_src[r["rule_id"]], "status": "pass" if not rule_fail[r["rule_id"]] else "fail",
              "problems": rule_fail[r["rule_id"]], "ir_hash": r["ir_hash"]} for r in compiled]
    passed = sum(c["status"] == "pass" for c in checks)
    deployed = [r for r in compiled if not rule_fail[r["rule_id"]]]
    report = {"passed": passed, "total": len(checks), "pass_rate": round(100 * passed / max(1, len(checks))),
              "tp": tp, "fp": fp, "fn": fn, "checks": checks, "rules": rules, "ok": passed == len(checks),
              "deployed": [r["rule_id"] for r in deployed], "rejected": [r["rule_id"] for r in compiled if rule_fail[r["rule_id"]]]}
    if deploy_path:
        os.makedirs(os.path.dirname(os.path.abspath(deploy_path)), exist_ok=True)
        with open(deploy_path, "w") as fh: json.dump(deployed, fh, indent=1)   # PASS -> deploy; FAIL -> rejected
    report["_deployed_ir"] = deployed
    return report
