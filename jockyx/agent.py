"""Endpoint agent: read-only collection -> POST to central server."""
import json, time, urllib.request
from .adapters import get_adapter


def push(server, events, token=None):
    req = urllib.request.Request(server.rstrip("/") + "/api/ingest", json.dumps({"events": [e.to_dict() for e in events]}).encode(),
                                 {"Content-Type": "application/json", **({"X-JOCKY-Token": token} if token else {})})
    with urllib.request.urlopen(req, timeout=30) as r: return json.load(r)


def run_agent(server, endpoint_id=None, interval=30, token=None, once=False, kinds=None):
    ad = get_adapter(endpoint_id)
    while True:
        evs = ad.collect(kinds)
        print(f"[agent {ad.endpoint_id}/{ad.os_name}] sent {push(server, evs, token)['ingested']} events", flush=True)
        if once: return
        time.sleep(interval)
