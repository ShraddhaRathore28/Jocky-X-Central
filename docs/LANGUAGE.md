# JOCKY language reference

```
RULE <id> ["name"]            # optional header (auto id ADHOC-nnn if omitted)
CLASS "threat class"          # optional metadata (before SCAN or after REPORT)
ATTACK "T1059.001", "T1071"   # optional MITRE ATT&CK references
EXPLAIN "custom explanation"  # optional
SCAN <TARGET> [WHERE <expr>]
REPORT [severity] LOW|MEDIUM|HIGH|CRITICAL
```

Operators: `=  !=  >  >=  <  <=  ~` (contains), `MATCHES "regex"`, `IN [a, b]`, `AND OR NOT ( )`.
Strings are case-insensitive; `name/parent/grandparent/process` also ignore a trailing `.exe`.

| Target | Fields |
|---|---|
| PROCESS | name parent grandparent path cmdline user pid(int) unsigned network external_network memory_anomaly(bool) child_count(int) |
| NETWORK | process dst_ip dst_port(int) direction protocol external(bool) |
| FILE | process path action |
| MEMORY_EVENT | process pid(int) kind region_perm unbacked(bool) |
| DRIVER_EVENT | name path unsigned in_baseline(bool) |

Safety: the language has only `SCAN` (read) and `REPORT` (alert). Rules cannot write, kill, inject, or load anything.
Type, field, operator, regex and severity errors are reported with line:column before any rule is deployed.

## IR (excerpt)
```json
{"ir_version":"1.0","rule_id":"JOCKY-RULE-017","target":"process",
 "query":{"op":"and","args":[{"op":"cmp","cmp":"eq","field":"parent","value":"powershell"}, "..."]},
 "action":{"type":"alert","severity":"HIGH","threat_class":"...","attack":["T1059.001"]},
 "telemetry_requirements":["network_conn","process_create"],"ir_hash":"sha256..."}
```
`telemetry_requirements` tells each OS adapter which event kinds it must collect, so rules stay OS-independent.
