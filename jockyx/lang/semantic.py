"""Semantic checker: validates targets, fields, types, operators, severities."""
import re
from .schema import TARGETS, SEVERITIES, ATTACK_NAMES
from .parser import JockyError

_OPS = {"str": {"eq", "ne", "contains", "matches", "in"}, "int": {"eq", "ne", "gt", "ge", "lt", "le", "in"},
        "bool": {"eq", "ne"}}
_PY = {"str": (str,), "int": (int, float), "bool": (bool,)}


def _check_expr(node, fields, errs):
    if node["op"] in ("and", "or"):
        for a in node["args"]: _check_expr(a, fields, errs)
        return
    if node["op"] == "not":
        return _check_expr(node["arg"], fields, errs)
    ln, col = node["pos"]
    f, typ = node["field"], fields.get(node["field"])
    if typ is None:
        errs.append(f"line {ln}:{col}: unknown field {f!r} (available: {', '.join(sorted(fields))})"); return
    if node["cmp"] not in _OPS[typ]:
        errs.append(f"line {ln}:{col}: operator {node['cmp']!r} not valid for {typ} field {f!r}"); return
    vals = node["value"] if node["cmp"] == "in" else [node["value"]]
    for v in vals:
        ok = isinstance(v, _PY[typ]) and not (typ == "int" and isinstance(v, bool))
        if not ok:
            errs.append(f"line {ln}:{col}: field {f!r} expects {typ}, got {v!r}")
    if node["cmp"] == "matches" and not errs:
        try: re.compile(node["value"])
        except re.error as e: errs.append(f"line {ln}:{col}: invalid regex: {e}")


def check(rules):
    errs, seen = [], set()
    for r in rules:
        if r["target"] not in TARGETS:
            ln, col = r["target_pos"]
            errs.append(f"line {ln}:{col}: unknown target {r['target']!r} (available: {', '.join(TARGETS)})")
            continue
        if r["severity"] not in SEVERITIES:
            ln, col = r["severity_pos"]
            errs.append(f"line {ln}:{col}: invalid severity {r['severity']!r} (use {'/'.join(SEVERITIES)})")
        if r["id"] in seen: errs.append(f"line {r['line']}: duplicate rule id {r['id']!r}")
        seen.add(r["id"])
        if r["where"]: _check_expr(r["where"], TARGETS[r["target"]], errs)
        for t in r["attack"]:
            if not re.fullmatch(r"T\d{4}(\.\d{3})?", t):
                errs.append(f"line {r['line']}: malformed ATT&CK id {t!r}")
    if errs: raise JockyError("semantic errors", errors=errs)
    return rules
