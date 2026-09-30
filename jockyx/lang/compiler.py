"""Compile JOCKY rules to the platform-independent JOCKY IR (plain JSON)."""
import hashlib, json
from .parser import parse
from .semantic import check
from .schema import TARGET_TELEMETRY, FIELD_TELEMETRY

IR_VERSION = "1.0"


def _lower(node):
    if node["op"] in ("and", "or"): return {"op": node["op"], "args": [_lower(a) for a in node["args"]]}
    if node["op"] == "not": return {"op": "not", "arg": _lower(node["arg"])}
    return {"op": "cmp", "cmp": node["cmp"], "field": node["field"], "value": node["value"]}


def _fields(node):
    if node is None: return set()
    if node["op"] in ("and", "or"): return set().union(*[_fields(a) for a in node["args"]])
    if node["op"] == "not": return _fields(node["arg"])
    return {node["field"]}


def canonical(obj): return json.dumps(obj, sort_keys=True, separators=(",", ":"))


def compile_source(src):
    rules = check(parse(src))
    out = []
    for r in rules:
        query = _lower(r["where"]) if r["where"] else {"op": "true"}
        need = set(TARGET_TELEMETRY[r["target"]]) | {"process_create"}
        for f in _fields(r["where"]): need |= FIELD_TELEMETRY.get(f, set())
        ir = {
            "ir_version": IR_VERSION, "rule_id": r["id"], "name": r["name"] or r["id"],
            "target": r["target"].lower(), "query": query,
            "action": {"type": "alert", "severity": r["severity"], "threat_class": r["class"] or "Suspicious Activity",
                       "attack": r["attack"], "explanation": r["explain"]},
            "telemetry_requirements": sorted(need),
        }
        ir["ir_hash"] = hashlib.sha256(canonical(ir).encode()).hexdigest()
        out.append(ir)
    return out


def compile_file(path):
    with open(path, encoding="utf-8") as fh:
        return compile_source(fh.read())
