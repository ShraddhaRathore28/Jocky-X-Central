"""Ubuntu/Linux adapter. Strictly read-only: psutil + /proc + /sys reads only."""
import os, re
from .base import Adapter, utcnow, is_external
from ..events import Event, stable_id

TRUSTED_PREFIXES = ("/usr/bin/", "/usr/sbin/", "/bin/", "/sbin/", "/usr/lib/", "/lib/", "/usr/libexec/", "/snap/")
JIT_ALLOW = {"java", "node", "chrome", "firefox", "code", "dotnet", "python3", "python", "electron", "pypy3"}


class UbuntuAdapter(Adapter):
    os_name = "Ubuntu"

    def _psutil(self):
        try:
            import psutil; return psutil
        except ImportError as e:
            raise RuntimeError("psutil is required for live collection: pip install psutil") from e

    def collect(self, kinds=None):
        ps, ev, ts = self._psutil(), [], utcnow()
        mk = lambda kind, key, **kw: Event(stable_id(self.endpoint_id, kind, *key), ts, self.endpoint_id, self.os_name, kind, **kw)
        procs = {}
        for p in ps.process_iter(["pid", "ppid", "name", "exe", "cmdline", "username", "create_time"]):
            i = p.info
            exe = i.get("exe") or ""
            procs[i["pid"]] = i
            if self.wants(kinds, "process_create"):
                # Package-managed system locations are treated as trusted (heuristic, not a signature check)
                ev.append(mk("process_create", (i["pid"], i.get("create_time")), pid=i["pid"], ppid=i["ppid"],
                             name=i["name"] or "", path=exe, cmdline=" ".join(i.get("cmdline") or [])[:500],
                             user=i.get("username") or "", signed=exe.startswith(TRUSTED_PREFIXES) if exe else None))
        if self.wants(kinds, "network_conn"):
            try:
                for c in ps.net_connections(kind="inet"):
                    if c.pid and c.raddr and c.status == "ESTABLISHED":
                        n = procs.get(c.pid, {}).get("name", "")
                        ev.append(mk("network_conn", (c.pid, c.raddr.ip, c.raddr.port), pid=c.pid, name=n,
                                     data={"dst_ip": c.raddr.ip, "dst_port": c.raddr.port, "protocol": "tcp",
                                           "direction": "outbound", "external": is_external(c.raddr.ip)}))
            except (ps.AccessDenied, PermissionError):
                pass  # needs elevated read access to see other users' sockets
        if self.wants(kinds, "memory_event"):
            for pid, i in procs.items():
                if (i["name"] or "") in JIT_ALLOW: continue
                try:
                    with open(f"/proc/{pid}/maps") as fh:
                        for line in fh:
                            parts = line.split(None, 5)
                            if len(parts) >= 5 and parts[1].startswith("rwx") and (len(parts) < 6 or not parts[5].strip()):
                                ev.append(mk("memory_event", (pid, parts[0]), pid=pid, name=i["name"] or "",
                                             data={"kind": "rwx_unbacked_region", "region_perm": "rwx",
                                                   "unbacked": True, "detail": parts[0]}))
                                break
                except (PermissionError, FileNotFoundError, ProcessLookupError):
                    continue
        if self.wants(kinds, "driver_load") and os.path.exists("/proc/modules"):
            mods = [l.split()[0] for l in open("/proc/modules")]
            base = self.baseline(mods)
            for m in mods:
                taint = ""
                try: taint = open(f"/sys/module/{m}/taint").read()
                except OSError: pass
                ev.append(mk("driver_load", (m,), name=m, signed="E" not in taint,   # 'E' = unsigned module taint
                             data={"in_baseline": m in base}))
        return ev
