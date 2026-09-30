"""Safe forensic primitives (targets) and the fields each one exposes.

JOCKY is read-only by construction: the language has no verbs other than
SCAN (query) and REPORT (raise an alert). There is no way to write, kill,
inject, or modify anything from a rule.
"""
TARGETS = {
    "PROCESS": {
        "name": "str", "parent": "str", "grandparent": "str", "path": "str",
        "cmdline": "str", "user": "str", "pid": "int", "unsigned": "bool",
        "network": "bool", "external_network": "bool", "memory_anomaly": "bool",
        "child_count": "int",
    },
    "NETWORK": {
        "process": "str", "dst_ip": "str", "dst_port": "int",
        "direction": "str", "protocol": "str", "external": "bool",
    },
    "FILE": {"process": "str", "path": "str", "action": "str"},
    "MEMORY_EVENT": {
        "process": "str", "pid": "int", "kind": "str",
        "region_perm": "str", "unbacked": "bool",
    },
    "DRIVER_EVENT": {"name": "str", "path": "str", "unsigned": "bool", "in_baseline": "bool"},
}
SEVERITIES = ("LOW", "MEDIUM", "HIGH", "CRITICAL")
NAME_FIELDS = {"name", "parent", "grandparent", "process"}  # compared without ".exe"

# Event kinds an adapter must collect for a given target / field.
TARGET_TELEMETRY = {
    "PROCESS": {"process_create"}, "NETWORK": {"network_conn"}, "FILE": {"file_op"},
    "MEMORY_EVENT": {"memory_event"}, "DRIVER_EVENT": {"driver_load"},
}
FIELD_TELEMETRY = {
    "network": {"network_conn"}, "external_network": {"network_conn"},
    "memory_anomaly": {"memory_event"},
}
ATTACK_NAMES = {
    "T1059.001": "Command and Scripting Interpreter: PowerShell",
    "T1059.003": "Command and Scripting Interpreter: Windows Command Shell",
    "T1059.004": "Command and Scripting Interpreter: Unix Shell",
    "T1204.002": "User Execution: Malicious File",
    "T1218.005": "System Binary Proxy Execution: Mshta",
    "T1055": "Process Injection",
    "T1068": "Exploitation for Privilege Escalation",
    "T1547.006": "Boot or Logon Autostart Execution: Kernel Modules and Extensions",
    "T1505.003": "Server Software Component: Web Shell",
    "T1036": "Masquerading",
    "T1003.008": "OS Credential Dumping: /etc/passwd and /etc/shadow",
    "T1571": "Non-Standard Port",
    "T1071": "Application Layer Protocol",
}
