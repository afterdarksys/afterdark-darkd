# Server and desktop deployment modes

Generate and review a profile before installing it:

```sh
afterdark-darkd config profile --mode server --platform linux > darkd-server.yaml
afterdark-darkd config profile --mode desktop --platform darwin > darkd-desktop.yaml
afterdark-darkd config profile --mode desktop --platform windows > darkd-windows.yaml
afterdark-darkd --config darkd-server.yaml config validate
```

Select `daemon.mode: server` or `daemon.mode: desktop` in YAML. The environment
variable `DARKD_DAEMON_MODE` overrides that selection; the global `--mode` flag has
highest priority. Explicit service settings in YAML override profile defaults.
Existing files without a mode retain legacy behavior. Switching profiles requires
a daemon restart. The mode is included in DarkAPI coverage telemetry.

Both are system-service profiles, not different privilege levels or a desktop GUI.
A desktop installation still needs the privileges required by its chosen sensors.
They retain authenticated local IPC, leave remote TCP administration and cloud
reporting off until configured, and never supply enrollment credentials.

| Default | Server | Desktop |
| --- | --- | --- |
| Process/connection polling | 10 seconds | 30 seconds |
| System metrics | 15 seconds | 60 seconds |
| Patch inventory | Hourly | Every four hours |
| TCP listener drift | Enabled | Disabled; can opt in |
| Canary file monitoring | Disabled; can opt in | Private daemon data directory |
| Local investigation | Seven days / 100,000 events | Same |
| Command-line capture | Off | Off |
| Automatic patch installation | Off | Off |
| Active remediation / new network listeners | Off | Off |

## Platform selection

- **Linux:** eBPF integration, process/network polling, Unix integrity files and
  persistence inventory. Native eBPF requires the kernel features and privileges
  of the selected build; service health reports actual availability.
- **macOS:** Endpoint Security integration, polling, Unix integrity files and
  launch-agent inventory. Endpoint Security requires signing/entitlements; the
  profile does not grant them. Data defaults to `/Library/Application Support/AfterDark`.
- **Windows:** ETW and registry integrations, polling, Windows hosts-file integrity,
  ProgramData storage and authenticated named-pipe IPC. Unix persistence scanning
  is disabled. This selects implemented interfaces; native driver/sensor runtime
  acceptance still requires a Windows host.

Generated paths are defaults. Review them for installations with redirected
Windows/ProgramData directories or custom data roots. Override watched files,
canary directories and other paths explicitly when required.

Placeholder cloud-metadata enforcement, device control, DLP, activity monitoring,
ML training and script policy execution stay disabled in both new profiles.
Optional memory scanning, detonation and application lockdown need explicit policy.

## Listener detection

The `network_drift` service observes TCP listeners. Its first successful snapshot
is a baseline. A listener absent from the previous successful snapshot produces
`network.listener_added` in the durable telemetry queue, with local address/port,
PID, exposure category and `listening: true`. It does not invent process start
identity or claim a port is Internet reachable. Collection or delivery errors
retain the previous baseline and degrade health. Individual event delivery is
at least once; a partial batch retry can repeat an observation. Restart establishes
a fresh baseline. UDP sockets and firewall reachability tests are not covered.

## Versioned investigation rules

`configs/investigation-platform-rules.json` adds six evidence-based review signals:
public-interface administrative listeners, cloud metadata connections, temporary
Linux executables, macOS Downloads executables, Windows user-writable executables,
and encoded PowerShell commands. These are investigation signals, not malware
verdicts. Command-line rules require explicit command-line collection.

```sh
afterdark-darkdadm investigate --db /var/lib/afterdark/investigation/events.db replay \
  --rules configs/investigation-platform-rules.json
```

The rule pack is replayed explicitly; it does not execute response actions or
silently install a new automatic detector. DarkAPI's existing worker independently
analyzes uploaded evidence. Enrollment and delivery configuration are documented
in `docs/DARKAPI_OPERATIONS.md`.
