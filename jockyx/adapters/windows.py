"""Windows adapter. Read-only: psutil, Get-AuthenticodeSignature, driverquery /si.

NOTE: developed against the documented APIs; run `python -m pytest` on a Windows
host to exercise it (CI runs it on windows-latest).
"""
import csv, io, json, subprocess
from .base import Adapter, utcnow, is_external
from ..events import Event, stable_id

_PS_SIG = ("$ErrorActionPreference='SilentlyContinue';"
           "$p=[Console]::In.ReadToEnd()|ConvertFrom-Json;"
           "$r=@($p|%{[pscustomobject]@{p=$_;s=[string](Get-AuthenticodeSignature -LiteralPath $_).Status}});"
           "ConvertTo-Json -InputObject $r -Compress")


class WindowsAdapter(Adapter):
    os_name = "Windows"

    def _psutil(self):
        try:
            import psutil; return psutil
        except ImportError as e:
            raise RuntimeError("psutil is required for live collection: pip install psutil") from e

    def _signatures(self, paths):
        """Return {path: True/False/None}. None = could not determine."""
        paths = sorted({p for p in paths if p})
        if not paths: return {}
        try:
            r = subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-Command", _PS_SIG],
                               input=json.dumps(paths), capture_output=True, text=True, timeout=120)
            data = json.loads(r.stdout or "[]")
            return {d["p"]: d["s"] == "Valid" for d in data}
        except (OSError, subprocess.SubprocessError, ValueError):
            return {}

    def collect(self, kinds=None):
        ps, ev, ts = self._psutil(), [], utcnow()
        mk = lambda kind, key, **kw: Event(stable_id(self.endpoint_id, kind, *key), ts, self.endpoint_id, self.os_name, kind, **kw)
        procs = {p.info["pid"]: p.info for p in ps.process_iter(["pid", "ppid", "name", "exe", "cmdline", "username", "create_time"])}
        if self.wants(kinds, "process_create"):
            sigs = self._signatures(i.get("exe") for i in procs.values())
            for pid, i in procs.items():
                exe = i.get("exe") or ""
                ev.append(mk("process_create", (pid, i.get("create_time")), pid=pid, ppid=i["ppid"], name=i["name"] or "",
                             path=exe, cmdline=" ".join(i.get("cmdline") or [])[:500], user=i.get("username") or "",
                             signed=sigs.get(exe)))
        if self.wants(kinds, "network_conn"):
            try:
                for c in ps.net_connections(kind="inet"):
                    if c.pid and c.raddr and c.status == "ESTABLISHED":
                        ev.append(mk("network_conn", (c.pid, c.raddr.ip, c.raddr.port), pid=c.pid,
                                     name=procs.get(c.pid, {}).get("name", ""),
                                     data={"dst_ip": c.raddr.ip, "dst_port": c.raddr.port, "protocol": "tcp",
                                           "direction": "outbound", "external": is_external(c.raddr.ip)}))
            except (ps.AccessDenied, PermissionError):
                pass
        if self.wants(kinds, "driver_load"):
            try:
                out = subprocess.run(["driverquery", "/si", "/fo", "csv"], capture_output=True, text=True, timeout=60).stdout
                rows = list(csv.DictReader(io.StringIO(out)))
                names = [r.get("InfName") or r.get("DeviceName") or "" for r in rows]
                base = self.baseline(names)
                for r, n in zip(rows, names):
                    ev.append(mk("driver_load", (n,), name=n, signed=(r.get("IsSigned", "").upper() == "TRUE"),
                                 data={"in_baseline": n in base, "device": r.get("DeviceName", "")}))
            except (OSError, subprocess.SubprocessError):
                pass
        # memory_event: live user-mode memory inspection is intentionally NOT implemented on Windows;
        # memory indicators come from replayed/synthetic telemetry or an EDR feed normalized to this schema.
        return ev
