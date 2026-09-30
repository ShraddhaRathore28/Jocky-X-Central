"""Evaluate a JOCKY IR query tree against an entity."""
import re
from ..lang.schema import NAME_FIELDS


def _norm(v, field):
    if isinstance(v, str):
        v = v.lower()
        return v.removesuffix(".exe") if field in NAME_FIELDS else v
    return v


def _cmp(node, ent):
    f, c, want = node["field"], node["cmp"], node["value"]
    have = ent.get(f)
    if have is None: return c == "ne"
    h = _norm(have, f)
    if c == "in": return h in [_norm(v, f) for v in want]
    if c == "matches": return re.search(want, str(have), re.I) is not None
    w = _norm(want, f)
    if c == "eq": return h == w
    if c == "ne": return h != w
    if c == "contains": return w in h
    return {"gt": h > w, "ge": h >= w, "lt": h < w, "le": h <= w}[c]


def evaluate(node, ent):
    op = node["op"]
    if op == "true": return True
    if op == "and": return all(evaluate(a, ent) for a in node["args"])
    if op == "or": return any(evaluate(a, ent) for a in node["args"])
    if op == "not": return not evaluate(node["arg"], ent)
    return _cmp(node, ent)


def render(node):
    """Human-readable form of a query (used in alert explanations)."""
    op = node["op"]
    if op == "true": return "(any)"
    if op in ("and", "or"): return "(" + f" {op.upper()} ".join(render(a) for a in node["args"]) + ")"
    if op == "not": return "NOT " + render(node["arg"])
    sym = {"eq": "=", "ne": "!=", "gt": ">", "ge": ">=", "lt": "<", "le": "<=", "contains": "~", "matches": "MATCHES", "in": "IN"}
    return f'{node["field"]} {sym[node["cmp"]]} {node["value"]!r}'
