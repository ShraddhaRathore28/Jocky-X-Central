"""Replay adapter: feeds recorded / synthetic telemetry through the same pipeline.

This is what the demos, tests and the CI detection lab use, so no real
malicious behaviour is ever required.
"""
import json
from ..events import Event
from .base import Adapter


class ReplayAdapter(Adapter):
    def __init__(self, trace_path=None, events=None, os_name="Ubuntu"):
        self.os_name = os_name
        self._trace = None
        if trace_path:
            with open(trace_path, encoding="utf-8") as fh: self._trace = json.load(fh)
            events = self._trace["events"]
        self._events = [Event.from_dict(e) for e in (events or [])]
        super().__init__(self._events[0].endpoint_id if self._events else "REPLAY")
        if self._events: self.os_name = self._events[0].os

    @property
    def meta(self): return (self._trace or {}).get("meta", {})

    def collect(self, kinds=None):
        return [e for e in self._events if self.wants(kinds, e.kind)]
