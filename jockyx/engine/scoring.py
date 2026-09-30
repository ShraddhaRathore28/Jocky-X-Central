"""Explainable risk fusion: every point of the score is tied to a named piece of evidence."""
import json, os

DEFAULT_CFG = os.path.join(os.path.dirname(__file__), "..", "..", "config", "scoring.json")
SEV_ORDER = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]


def load_config(path=None):
    with open(path or DEFAULT_CFG, encoding="utf-8") as fh: return json.load(fh)


def _low(s): return (s or "").lower()


def _ind(cfg, key, label, detail):
    return {"id": key, "label": label, "points": cfg["weights"][key], "detail": detail}


def _process_indicators(p, cfg, out):
    par = _low(p.get("parent")).removesuffix(".exe")
    me = _low(p.get("name")).removesuffix(".exe")
    if par in cfg["suspicious_parents"] and me not in cfg["suspicious_parents"]:
        out.append(_ind(cfg, "suspicious_ancestry", "Suspicious process ancestry", f"{p['parent']} -> {p['name']}"))
    if p.get("unsigned"):
        out.append(_ind(cfg, "unsigned_executable", "Unsigned executable", p.get("path") or p["name"]))
    if p.get("external_network") and (p.get("unsigned") or any(i["id"] == "suspicious_ancestry" for i in out)):
        out.append(_ind(cfg, "abnormal_network", "Abnormal network connection", f"{p['name']} made an external connection"))
    if p.get("memory_anomaly"):
        out.append(_ind(cfg, "suspicious_memory", "Suspicious memory behavior", "anomalous memory-event telemetry"))
    if any(m in _low(p.get("path")) for m in cfg["temp_markers"]):
        out.append(_ind(cfg, "execution_from_temp", "Execution from temporary location", p["path"]))


def indicators(ent, cfg):
    out, k = [], ent["_kind"]
    if k == "process":
        _process_indicators(ent, cfg, out)
        return out
    if ent.get("_proc"): _process_indicators(ent["_proc"], cfg, out)
    out[:] = [i for i in out if i["id"] in ("suspicious_ancestry", "unsigned_executable", "execution_from_temp")]
    if k == "network" and ent.get("external") and ent.get("dst_port") not in cfg["usual_ports"]:
        out.append(_ind(cfg, "unusual_port", "Unusual destination port", f"{ent['dst_ip']}:{ent['dst_port']}"))
    if k == "memory_event":
        out.append(_ind(cfg, "suspicious_memory", "Suspicious memory behavior", f"{ent['kind']} ({ent['region_perm']}) in {ent['process']}"))
    if k == "file" and any(s in _low(ent.get("path")) for s in cfg["sensitive_paths"]):
        out.append(_ind(cfg, "sensitive_file_access", "Sensitive file access", f"{ent['action']} {ent['path']} by {ent['process']}"))
    if k == "driver_event":
        if ent["unsigned"]: out.append(_ind(cfg, "unsigned_driver", "Unsigned driver/module", ent["name"]))
        if not ent["in_baseline"]: out.append(_ind(cfg, "driver_not_in_baseline", "Driver not in known-good baseline", ent["name"]))
    return out


def fuse(ent, rule_sev, cfg):
    inds = indicators(ent, cfg)
    score = min(100, sum(i["points"] for i in inds))
    band = next(b for b in ("CRITICAL", "HIGH", "MEDIUM", "LOW") if score >= cfg["bands"][b])
    final = max(rule_sev, band, key=SEV_ORDER.index)
    return score, band, final, inds
