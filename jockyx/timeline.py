"""Forensic Time Machine: correlate events into a chronological incident narrative."""
from .engine.features import index, ancestors, descendants


def label(e, procs):
    d = e.data
    if e.kind == "process_create":
        par = procs.get(e.ppid)
        return f"Process Created: {e.name} (pid {e.pid}, parent {par.name if par else e.ppid})"
    if e.kind == "network_conn":
        return f"Network Connection: {e.name} -> {d.get('dst_ip')}:{d.get('dst_port')}" + (" [external]" if d.get("external") else "")
    if e.kind == "file_op": return f"File {d.get('action')}: {d.get('path')} by {e.name}"
    if e.kind == "memory_event": return f"Suspicious Memory Event: {d.get('kind')} in {e.name}"
    if e.kind == "driver_load": return f"Driver Loaded: {e.name}" + ("" if e.signed is not False else " [unsigned]")
    return e.kind


def _entry(e, procs, flagged=False):
    return {"ts": e.ts, "event_id": e.event_id, "kind": e.kind, "pid": e.pid, "label": label(e, procs), "flagged": flagged}


def build_timeline(alert, events):
    """Events causally linked to the alert (ancestors, the entity, its descendants) + the ALERT marker."""
    evs = [e for e in events if e.endpoint_id == alert["endpoint_id"]]
    procs, kids = index(evs)
    refs, pid = set(alert["timeline_refs"]), alert.get("pid")
    related = set(pid is not None and [pid] or [])
    if pid is not None:
        related |= {a.pid for a in ancestors(procs, pid)} | set(descendants(kids, pid))
    chosen = [e for e in evs if e.event_id in refs or (e.pid in related and pid is not None)]
    if not chosen:
        chosen = [e for e in evs if e.event_id in refs]
    out = [_entry(e, procs, e.event_id in refs) for e in sorted(chosen, key=lambda e: (e.ts, e.event_id))]
    out.append({"ts": alert["timestamp"], "event_id": alert["alert_id"], "kind": "alert", "pid": pid,
                "label": f'ALERT GENERATED: {alert["severity"]} - {alert["rule_id"]}', "flagged": True})
    return out


def time_machine(events, endpoint_id, center_ts, before=60, after=60):
    """Everything on an endpoint within [center-before, center+after] seconds (rewind/fast-forward)."""
    from datetime import datetime, timedelta
    p = lambda s: datetime.strptime(s, "%Y-%m-%dT%H:%M:%SZ")
    c = p(center_ts)
    evs = [e for e in events if e.endpoint_id == endpoint_id]
    procs, _ = index(evs)
    win = [e for e in evs if c - timedelta(seconds=before) <= p(e.ts) <= c + timedelta(seconds=after)]
    return [_entry(e, procs) for e in sorted(win, key=lambda e: (e.ts, e.event_id))]
