"""Evidence bundles: tamper-evident zip (SHA-256 manifest) + markdown investigation report."""
import hashlib, io, json, zipfile
from .lang.compiler import canonical


def render_report(alert, timeline):
    L = [f'# JOCKY-X Investigation Report: {alert["alert_id"]}', "",
         f'- **Severity:** {alert["severity"]}   **Threat score:** {alert["score"]}/100   **Confidence:** {alert["confidence_score"]}',
         f'- **Endpoint:** {alert["endpoint_id"]} ({alert["os"]})   **Time:** {alert["timestamp"]}',
         f'- **Rule:** {alert["rule_id"]} - {alert["rule_name"]}   **Class:** {alert["threat_class"]}',
         f'- **Process:** {alert.get("process")}  {alert.get("process_path") or ""}', "",
         "## Why this alert was generated", alert["explanation"], "", "## Supporting evidence"]
    L += [f'- {s}' for s in alert["supporting_evidence"]]
    L += ["", "## Score breakdown", "| Indicator | Points | Detail |", "|---|---|---|"]
    L += [f'| {i["label"]} | +{i["points"]} | {i["detail"]} |' for i in alert["score_breakdown"]] or ["| (none) | 0 | |"]
    if alert["attack"]:
        L += ["", "## ATT&CK references"] + [f'- {a["id"]} {a["name"]}' for a in alert["attack"]]
    L += ["", "## Incident timeline"] + [f'- `{t["ts"]}` {"**" if t["flagged"] else ""}{t["label"]}{"**" if t["flagged"] else ""}' for t in timeline]
    return "\n".join(L) + "\n"


def build_bundle(alert, timeline, events, ir=None):
    """Return zip bytes containing alert, timeline, raw events, rule IR, report and a hash manifest."""
    refs = set(alert["timeline_refs"]) | {t["event_id"] for t in timeline}
    files = {
        "alert.json": json.dumps(alert, indent=2), "timeline.json": json.dumps(timeline, indent=2),
        "events.json": json.dumps([e.to_dict() for e in events if e.event_id in refs], indent=2),
        "rule_ir.json": json.dumps(ir or {}, indent=2), "report.md": render_report(alert, timeline),
    }
    manifest = "\n".join(f"{hashlib.sha256(v.encode()).hexdigest()}  {k}" for k, v in sorted(files.items())) + "\n"
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for k, v in files.items(): z.writestr(k, v)
        z.writestr("MANIFEST.sha256", manifest)
    return buf.getvalue()
