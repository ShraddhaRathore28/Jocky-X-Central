"""Feature extraction: turn raw events (one endpoint) into queryable entities."""
from collections import defaultdict


def _base(name): return (name or "").lower().removesuffix(".exe")


def index(events):
    """Shared lookups used by features, timeline and scoring."""
    procs, kids = {}, defaultdict(list)
    for e in events:
        if e.kind == "process_create":
            procs[e.pid] = e
    for pid, e in procs.items():
        kids[e.ppid].append(pid)
    return procs, kids


def ancestors(procs, pid, limit=8):
    out, seen = [], {pid}
    e = procs.get(pid)
    while e and e.ppid in procs and e.ppid not in seen and len(out) < limit:
        out.append(procs[e.ppid]); seen.add(e.ppid); e = procs[e.ppid]
    return out


def descendants(kids, pid, limit=200):
    out, stack = [], list(kids.get(pid, []))
    while stack and len(out) < limit:
        p = stack.pop()
        out.append(p); stack.extend(kids.get(p, []))
    return out


def build_entities(events):
    """Return {target: [entity dict]}; keys starting with '_' are internal."""
    procs, kids = index(events)
    by_pid = defaultdict(lambda: defaultdict(list))
    for e in events:
        if e.pid is not None: by_pid[e.pid][e.kind].append(e)
    ents = {"process": {}, "network": [], "file": [], "memory_event": [], "driver_event": []}

    for pid, e in procs.items():
        anc = ancestors(procs, pid)
        net, mem = by_pid[pid]["network_conn"], by_pid[pid]["memory_event"]
        evs = [e] + net + mem + by_pid[pid]["file_op"]
        ents["process"][pid] = {
            "name": e.name, "parent": anc[0].name if anc else None,
            "grandparent": anc[1].name if len(anc) > 1 else None, "path": e.path, "cmdline": e.cmdline,
            "user": e.user, "pid": pid, "unsigned": e.signed is False, "network": bool(net),
            "external_network": any(n.data.get("external") for n in net), "memory_anomaly": bool(mem),
            "child_count": len(kids.get(pid, [])),
            "_kind": "process", "_pid": pid, "_events": [x.event_id for x in evs],
            "_ts": max(x.ts for x in evs), "_endpoint": e.endpoint_id, "_os": e.os,
            "_ancestors": [a.name for a in anc],
        }
    for e in events:
        if e.kind == "process_create": continue
        pe = ents["process"].get(e.pid)
        base = {"_events": [e.event_id] + (pe["_events"][:1] if pe else []), "_ts": e.ts, "_endpoint": e.endpoint_id,
                "_os": e.os, "_pid": e.pid, "_proc": pe}
        d = e.data
        if e.kind == "network_conn":
            ents["network"].append({**base, "_kind": "network", "process": e.name, "dst_ip": d.get("dst_ip"),
                                    "dst_port": d.get("dst_port"), "direction": d.get("direction"),
                                    "protocol": d.get("protocol"), "external": bool(d.get("external"))})
        elif e.kind == "file_op":
            ents["file"].append({**base, "_kind": "file", "process": e.name, "path": d.get("path", ""), "action": d.get("action")})
        elif e.kind == "memory_event":
            ents["memory_event"].append({**base, "_kind": "memory_event", "process": e.name, "pid": e.pid,
                                         "kind": d.get("kind"), "region_perm": d.get("region_perm"), "unbacked": bool(d.get("unbacked"))})
        elif e.kind == "driver_load":
            base["_pid"] = None
            ents["driver_event"].append({**base, "_kind": "driver_event", "name": e.name, "path": e.path,
                                         "unsigned": e.signed is False, "in_baseline": bool(d.get("in_baseline", True))})
    ents["process"] = list(ents["process"].values())
    return ents
