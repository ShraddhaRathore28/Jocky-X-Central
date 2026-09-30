import ipaddress, json, os, socket
from datetime import datetime, timezone


def utcnow(): return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def is_external(ip):
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return not (a.is_private or a.is_loopback or a.is_link_local or a.is_multicast or a.is_unspecified)


class Adapter:
    """OS adapter contract: read-only collection normalized to the common Event schema."""
    os_name = "Unknown"

    def __init__(self, endpoint_id=None):
        self.endpoint_id = endpoint_id or socket.gethostname()

    def collect(self, kinds=None):
        """Return list[Event]. `kinds` (from IR telemetry_requirements) limits collection."""
        raise NotImplementedError

    def wants(self, kinds, kind): return kinds is None or kind in kinds

    # baseline of "known" drivers/modules, learned on first run (read/write only to our own state dir)
    def _baseline_path(self):
        d = os.path.join(os.path.expanduser("~"), ".jockyx"); os.makedirs(d, exist_ok=True)
        return os.path.join(d, f"driver_baseline_{self.os_name.lower()}.json")

    def baseline(self, current):
        p = self._baseline_path()
        if os.path.exists(p):
            with open(p) as fh: return set(json.load(fh))
        with open(p, "w") as fh: json.dump(sorted(current), fh)
        return set(current)   # first run learns the baseline
