# Safety & scope
JOCKY-X is **defensive only**. It implements no persistence, credential theft, EDR tampering, BYOVD, process hollowing
or covert C2. Evasive techniques appear only as *detection targets*: rules match indicators in telemetry.
- Live adapters only read (psutil, /proc, /sys, `Get-AuthenticodeSignature`, `driverquery /si`). The only file they write is their own driver baseline in `~/.jockyx/`.
- Demonstrations use replayed synthetic traces in `traces/`; no malicious code is executed.
- Every alert carries supporting evidence and an explanation.
