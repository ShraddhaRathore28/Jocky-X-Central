"""Detection engine: IR rules x entities -> explainable alerts."""
import hashlib
from collections import defaultdict
from .features import build_entities
from .executor import evaluate, render
from .scoring import fuse, load_config
from ..lang.schema import ATTACK_NAMES


class Engine:
    def __init__(self, rules_ir, scoring_cfg=None):
        self.rules = list(rules_ir)
        self.cfg = scoring_cfg or load_config()

    @property
    def telemetry_requirements(self):
        return sorted({k for r in self.rules for k in r["telemetry_requirements"]})

    def analyze(self, events):
        """events: list[Event] (any mix of endpoints). Returns list of alert dicts (deterministic)."""
        alerts, by_ep = [], defaultdict(list)
        for e in events: by_ep[e.endpoint_id].append(e)
        for ep, evs in by_ep.items():
            ents = build_entities(evs)
            for r in self.rules:
                for ent in ents.get(r["target"], []):
                    if evaluate(r["query"], ent):
                        alerts.append(self._alert(r, ent))
        return sorted(alerts, key=lambda a: (a["timestamp"], a["alert_id"]))

    def _alert(self, r, ent):
        act = r["action"]
        score, band, sev, inds = fuse(ent, act["severity"], self.cfg)
        key = f'{r["rule_id"]}|{ent["_endpoint"]}|{ent["_kind"]}|{ent.get("_pid")}|{ent["_ts"]}|{ent["_events"][0]}'
        h = hashlib.sha1(key.encode()).hexdigest()[:6].upper()
        evidence = [f'{i["label"]}: {i["detail"]}' for i in inds] or [f'Rule condition matched: {render(r["query"])}']
        p = ent if ent["_kind"] == "process" else (ent.get("_proc") or {})
        return {
            "alert_id": f'JX-{ent["_ts"][:4]}-{h}', "timestamp": ent["_ts"], "endpoint_id": ent["_endpoint"],
            "os": ent["_os"], "severity": sev, "threat_class": act["threat_class"],
            "confidence_score": round(score / 100, 2), "supporting_evidence": evidence,
            "timeline_refs": list(dict.fromkeys(ent["_events"])), "rule_id": r["rule_id"],
            "explanation": act["explanation"] or (
                f'Rule {r["rule_id"]} ({r["name"]}) matched [{render(r["query"])}]. {len(inds)} correlated indicator(s) '
                f'total {score}/100 (score band {band}; rule severity {act["severity"]}) -> {sev}.'),
            "rule_name": r["name"], "target": r["target"], "score": score, "score_band": band,
            "rule_severity": act["severity"], "score_breakdown": inds, "pid": ent.get("_pid"),
            "process": p.get("name") or ent.get("name"), "process_path": p.get("path", ""),
            "attack": [{"id": t, "name": ATTACK_NAMES.get(t, "")} for t in act["attack"]],
            "ir_hash": r["ir_hash"],
        }
