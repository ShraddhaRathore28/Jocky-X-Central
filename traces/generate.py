"""Generates the synthetic/benign replay traces used by tests, CI and the demo.

Traces are hand-authored telemetry (no real malicious code is executed). Each carries the
detections it is EXPECTED to produce, which is what the CI detection lab checks.
Run:  python traces/generate.py
"""
import json, os

HERE = os.path.dirname(os.path.abspath(__file__))


class T:
    """Tiny builder: each helper appends one normalized event at 10:31:00Z + dt seconds."""

    def __init__(self, name, desc, endpoint, os_, expect):
        self.meta = {"name": name, "description": desc, "expect": {"rules": sorted(expect)}}
        self.ep, self.os, self.ev, self.n = endpoint, os_, [], 100

    def _e(self, kind, dt, **kw):
        self.n += 1
        s = 31 * 60 + dt
        self.ev.append(dict(event_id=f"EVT-{self.n}", ts=f"2026-09-30T10:{s // 60:02d}:{s % 60:02d}Z",
                            endpoint_id=self.ep, os=self.os, kind=kind, **kw))

    def proc(self, dt, pid, ppid, name, path, signed=True, cmd="", user="user"):
        self._e("process_create", dt, pid=pid, ppid=ppid, name=name, path=path, cmdline=cmd or name, user=user, signed=signed)

    def net(self, dt, pid, name, ip, port, external=True):
        self._e("network_conn", dt, pid=pid, name=name,
                data=dict(dst_ip=ip, dst_port=port, protocol="tcp", direction="outbound", external=external))

    def mem(self, dt, pid, name, kind="rwx_unbacked_region"):
        self._e("memory_event", dt, pid=pid, name=name, data=dict(kind=kind, region_perm="rwx", unbacked=True))

    def file(self, dt, pid, name, path, action):
        self._e("file_op", dt, pid=pid, name=name, data=dict(path=path, action=action))

    def drv(self, dt, name, path, signed, in_base):
        self._e("driver_load", dt, name=name, path=path, signed=signed, data=dict(in_baseline=in_base))

    def save(self):
        with open(os.path.join(HERE, self.meta["name"] + ".json"), "w") as fh:
            json.dump({"meta": self.meta, "events": self.ev}, fh, indent=1)


def build(name, desc, ep, os_, expect):
    return T(name, desc, ep, os_, expect)


def main():
    W, U = "Windows", "Ubuntu"
    # ---- malicious-behaviour SYNTHETIC traces ----
    t = build("win_powershell_chain", "explorer -> powershell -> unsigned updater; external net + rwx memory", "WIN-04", W,
              ["JOCKY-RULE-017", "JOCKY-RULE-003", "JOCKY-RULE-009"])
    t.proc(0, 4000, 1, "explorer.exe", r"C:\Windows\explorer.exe")
    t.proc(1, 4100, 4000, "powershell.exe", r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe")
    t.proc(2, 4200, 4100, "updater.exe", r"C:\ProgramData\Updater\updater.exe", signed=False, cmd="updater.exe --sync")
    t.net(3, 4200, "updater.exe", "203.0.113.50", 443)
    t.mem(4, 4200, "updater.exe")
    t.save()

    t = build("win_office_macro_chain", "winword -> cmd -> powershell (parent-child anomaly only)", "WIN-05", W, ["JOCKY-RULE-001"])
    t.proc(0, 5000, 1, "explorer.exe", r"C:\Windows\explorer.exe")
    t.proc(1, 5100, 5000, "WINWORD.EXE", r"C:\Program Files\Microsoft Office\WINWORD.EXE")
    t.proc(2, 5200, 5100, "cmd.exe", r"C:\Windows\System32\cmd.exe")
    t.save()

    t = build("win_script_host_net", "wscript reaches an external host", "WIN-06", W, ["JOCKY-RULE-002"])
    t.proc(0, 6000, 1, "explorer.exe", r"C:\Windows\explorer.exe")
    t.proc(1, 6100, 6000, "wscript.exe", r"C:\Windows\System32\wscript.exe")
    t.net(2, 6100, "wscript.exe", "198.51.100.7", 443)
    t.save()

    t = build("win_unsigned_driver", "unsigned driver appears that is not in baseline", "WIN-08", W, ["JOCKY-RULE-004"])
    t.drv(0, "ntfs.sys", r"C:\Windows\System32\drivers\ntfs.sys", True, True)
    t.drv(1, "mystery_drv.sys", r"C:\Windows\System32\drivers\mystery_drv.sys", False, False)
    t.save()

    t = build("ubuntu_webshell", "nginx -> sh -> curl to external host", "UBU-01", U, ["JOCKY-RULE-005"])
    t.proc(0, 900, 1, "nginx", "/usr/sbin/nginx")
    t.proc(1, 901, 900, "sh", "/usr/bin/dash", cmd="sh -c id")
    t.proc(2, 902, 901, "curl", "/usr/bin/curl")
    t.net(3, 902, "curl", "192.0.2.10", 443)
    t.save()

    t = build("ubuntu_tmp_beacon", "unsigned binary in /tmp beacons to port 4444, rwx region", "UBU-02", U,
              ["JOCKY-RULE-006", "JOCKY-RULE-008", "JOCKY-RULE-003", "JOCKY-RULE-009"])
    t.proc(0, 1000, 1, "systemd", "/usr/lib/systemd/systemd")
    t.proc(1, 1500, 1000, ".x", "/tmp/.x", signed=False)
    t.net(2, 1500, ".x", "203.0.113.99", 4444)
    t.mem(3, 1500, ".x")
    t.save()

    t = build("ubuntu_shadow_read", "unexpected process reads /etc/shadow", "UBU-03", U, ["JOCKY-RULE-007"])
    t.proc(0, 2000, 1, "bash", "/usr/bin/bash")
    t.proc(1, 2100, 2000, "reader", "/usr/local/bin/reader", signed=False)
    t.file(2, 2100, "reader", "/etc/shadow", "read")
    t.save()

    # ---- BENIGN traces: must produce NO alerts (false-positive regression) ----
    t = build("benign_win_admin", "admin runs signed git via PowerShell; signed driver load", "WIN-07", W, [])
    t.proc(0, 7000, 1, "explorer.exe", r"C:\Windows\explorer.exe")
    t.proc(1, 7100, 7000, "powershell.exe", r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe")
    t.proc(2, 7200, 7100, "git.exe", r"C:\Program Files\Git\cmd\git.exe")
    t.net(3, 7200, "git.exe", "140.82.112.3", 443)
    t.drv(4, "ntfs.sys", r"C:\Windows\System32\drivers\ntfs.sys", True, True)
    t.save()

    t = build("benign_ubuntu_server", "nginx worker, apt update, passwd reads shadow", "UBU-04", U, [])
    t.proc(0, 300, 1, "nginx", "/usr/sbin/nginx")
    t.proc(1, 301, 300, "nginx", "/usr/sbin/nginx")
    t.net(2, 301, "nginx", "198.51.100.20", 443)
    t.proc(3, 400, 1, "apt", "/usr/bin/apt")
    t.net(4, 400, "apt", "91.189.91.39", 80)
    t.proc(5, 410, 1, "passwd", "/usr/bin/passwd")
    t.file(6, 410, "passwd", "/etc/shadow", "read")
    t.save()


if __name__ == "__main__":
    main()
