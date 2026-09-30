"""Standardized, OS-independent event schema shared by every adapter."""
import hashlib
from dataclasses import dataclass, field, asdict
from typing import Optional

KINDS = ("process_create", "network_conn", "file_op", "memory_event", "driver_load")


@dataclass
class Event:
    event_id: str
    ts: str                      # ISO-8601 UTC, e.g. 2026-09-30T10:31:02Z
    endpoint_id: str
    os: str                      # "Windows" | "Ubuntu"
    kind: str
    pid: Optional[int] = None
    ppid: Optional[int] = None
    name: str = ""
    path: str = ""
    cmdline: str = ""
    user: str = ""
    signed: Optional[bool] = None    # None = unknown
    data: dict = field(default_factory=dict)

    def to_dict(self): return asdict(self)

    @staticmethod
    def from_dict(d):
        d = dict(d)
        d.setdefault("data", {})
        return Event(**{k: d[k] for k in Event.__dataclass_fields__ if k in d})


def stable_id(*parts):
    return "EVT-" + hashlib.sha1("|".join(map(str, parts)).encode()).hexdigest()[:10].upper()
