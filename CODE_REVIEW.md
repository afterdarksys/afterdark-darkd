---
status: findings
review_date: 2026-09-15
reviewed_commit: 97345b8714e6678c61b6a322af8a8916a869e408
scope: repository platform-readiness review
findings:
  p1: 12
  p2: 2
  total: 14
---

# Code review: platform readiness

## Assessment

The repository has useful Go services, platform adapters, a plugin SDK, and detection algorithms. It is not yet a reliable advanced endpoint security agent: some controls report success without taking action, telemetry paths are disconnected, and native platform builds have blockers. Repairing those contracts should precede adding more detectors.

This is a review of the current implementation, not a pull-request diff. Findings below are either reproduced by build/test commands or supported by specific call paths. Source inspection concentrated on daemon lifecycle, IPC, platform adapters, native sensors, patch compliance, firewall integration, and event forwarding. It was not an exhaustive audit of the dashboard, deployment integrations, every plugin, or dependencies. No production code was changed.

Priority: **P1** = fix before relying on the affected capability or shipping its platform; **P2** = address in the next implementation cycle. There is no claim of a demonstrated remote exploit.

## Findings

### R01 — P1: RPCs acknowledge operations that never happen

**Evidence:** [internal/ipc/server.go](internal/ipc/server.go), `StartService` (line 780), `StopService`, `RestartService`, `ReloadConfig`, `Shutdown`, and `ScanProcessMemory`.

These methods return successful responses without invoking the corresponding daemon/service operations. `TriggerScan` also reports a started scan for an unknown scan type or an unavailable service. `CheckBulk` returns `IsThreat: false` for every indicator without consulting threat intelligence. This gives administrators and automation false confirmation of protective actions and clean results.

**Fix:** connect implemented operations to typed service interfaces and return operation IDs backed by real state. Return `Unimplemented`, `Unavailable`, or `InvalidArgument` for unsupported requests. Bulk lookups must use the same lookup path as individual queries and distinguish unavailable intelligence from a negative match.

**Acceptance:** contract tests verify that each successful operation changes observable state; unknown services, unsupported scans, unavailable feeds, and a known malicious bulk indicator produce the appropriate outcome.

### R02 — P1: Linux and Windows patch stubs certify hosts as compliant

**Evidence:** [internal/platform/linux/patches.go](internal/platform/linux/patches.go), lines 14–25; [internal/platform/windows/patches.go](internal/platform/windows/patches.go), lines 16–27; [internal/service/patch/service.go](internal/service/patch/service.go), lines 193–221 and 287–321.

Installed and available patch queries return empty slices with no error on both platforms. The patch service treats the resulting empty missing-patch set as `Compliant: true`. An enabled scan therefore certifies a host whose update state was never examined.

**Fix:** immediately return an unsupported capability outcome and expose unknown compliance. Implement package-manager and Windows Update adapters with collection timestamps, provenance, and explicit collection errors.

**Acceptance:** a host with pending updates cannot become compliant because collection is unavailable, returns a parsing error, or lacks permission.

### R03 — P1: macOS patch deadlines reset on every scan

**Evidence:** [internal/platform/macos/patches.go](internal/platform/macos/patches.go), `parseAvailableUpdates`, line 102; [internal/service/patch/service.go](internal/service/patch/service.go), lines 307–311.

The macOS parser assigns `ReleasedAt: time.Now()` each time it discovers an available patch. The compliance service computes its deadline from that timestamp plus the configured urgency. With a positive urgency, each new scan moves the deadline forward, so a persistently missing patch can remain compliant indefinitely.

**Fix:** use authoritative release metadata where available; otherwise persist a first-observed timestamp and clearly label the deadline basis. Keep unknown release dates separate from actual publication dates.

**Acceptance:** scan the same missing patch across simulated days and a daemon restart; its deadline remains fixed and it becomes overdue at the expected time.

### R04 — P1: native telemetry and detection are not connected end to end

**Evidence:** [internal/service/ebpf/service_linux.go](internal/service/ebpf/service_linux.go), `Start` and `Health`; [internal/service/esf/service_darwin.go](internal/service/esf/service_darwin.go), `handleEvent`; [internal/platform/windows/etw/session.go](internal/platform/windows/etw/session.go), `processLoop`; [internal/daemon/services.go](internal/daemon/services.go), `C2DetectionService.Start`.

Linux eBPF startup loads no program and attaches no probe, yet reports “ebpf probes active.” macOS ES and Windows ETW handlers only log events. The C2 wrapper starts no analysis loop, and the repository has no production caller of `BeaconAnalyzer.RecordConnection`. Likewise, no production caller invokes the SIEM service's `IngestLog`. Enabling these components does not establish a sensor-to-detector-to-alert path. The macOS memory reader also returns empty/nil successful results from placeholder methods.

**Fix:** report each missing capability accurately, then connect normalized sensor events to correlation and durable alert delivery. Establish explicit coverage, last-event, error, and loss metrics.

**Acceptance:** a harmless process/connection fixture on each supported sensor yields an attributed event, a deterministic detection where applicable, and an exported alert. A missing sensor cannot report active coverage.

### R05 — P1: DNS log capture stops following files after its first EOF

**Evidence:** [internal/service/dnstunnel/capture.go](internal/service/dnstunnel/capture.go), lines 85–108.

`tailLog` seeks to the end and repeatedly reuses one `bufio.Scanner`. Once the scanner reaches EOF, subsequent scans do not resume when the file grows. Usually the first timer tick reaches EOF before a DNS line arrives, leaving the detector silently starved. Rotation is also unhandled. Separately, the BIND expression captures domain/type in the opposite order from the dnsmasq expression, but `parseLogLine` interprets all captures identically.

**Fix:** use a tailing implementation that handles EOF, partial lines, truncation, and rotation. Decode each log format with its own field mapping and expose “no supported source” as a coverage gap. The pcap and DNS-specific ETW implementations must remain unavailable until implemented.

**Acceptance:** append queries after an idle EOF, rotate and truncate the file, and verify dnsmasq/BIND fields. Query collection must resume without restarting the daemon.

### R06 — P1: Linux firewall enablement has unsafe and ineffective paths

**Evidence:** [internal/platform/linux/platform.go](internal/platform/linux/platform.go), lines 184–190; [plugins/firewall-linux/main.go](plugins/firewall-linux/main.go), `initNftables` and `initIptables`.

The platform adapter treats creation of an empty nftables table as an enabled firewall; it adds no hooked chain or policy. Its fallback changes the global iptables INPUT policy to DROP without first preserving established or management traffic. When called on a host without suitable existing rules, that can disconnect administration. The separate firewall plugin suppresses initialization failures and returns success, so it can also report enablement after setup failed. These are source-level findings; firewall commands were not executed on the review host.

**Fix:** consolidate control behind a tested adapter; stage changes in owned tables/chains, preserve management and established connections, validate the result, and implement timed rollback. Propagate initialization failures.

**Acceptance:** isolated Linux VM tests cover empty rulesets, nft failure, iptables fallback, IPv4/IPv6, repeated enablement, rollback, and preservation of unrelated rules and management access.

### R07 — P1: the daemon cannot load the supplied firewall plugins

**Evidence:** [internal/plugin/host.go](internal/plugin/host.go), `PluginMap`, lines 31–37, and `getPluginInfo`; [pkg/pluginsdk/sdk.go](pkg/pluginsdk/sdk.go), `ServeFirewallPlugin`, line 560.

The SDK serves firewall plugins under the `firewall` interface, but the host only registers and dispenses service, datasource, storage, reporter, and CLI interfaces. It also omits firewall handling when extracting plugin information. A valid firewall plugin therefore fails loading with “plugin does not implement any known interface.” Compiling these binaries does not make firewall management available to the daemon.

**Fix:** implement the host-side firewall gRPC adapter, registration, configuration, lifecycle, and service lookup; add a real SDK/host compatibility test.

**Acceptance:** launch a harmless fake firewall plugin as a subprocess, negotiate it through the real host, configure it, and verify a recorded operation and shutdown.

### R08 — P1: Windows daemon does not compile

**Reproduced:** Windows amd64 cross-build fails at [internal/plugin/host.go](internal/plugin/host.go), line 111: `undefined: syscall.Stat_t`.

POSIX ownership validation is in a shared source file. Additional source inspection finds unresolved `debug.Run` and `svcdebug.Log` identifiers in [cmd/afterdark-darkd/service_windows.go](cmd/afterdark-darkd/service_windows.go), lines 46 and 63. The compiler stopped at the plugin package, so the latter are identified statically rather than from that build's output.

**Fix:** split plugin file-trust checks into OS-specific implementations, use Windows ACL checks, repair service imports, and continuously compile the Windows daemon and CLI.

**Acceptance:** native Windows build and service lifecycle tests pass; an ordinary user cannot replace a trusted privileged plugin. Cross-compilation alone is insufficient for service validation.

### R09 — P1: Windows IPC server and client use incompatible transports

**Evidence:** [internal/ipc/server.go](internal/ipc/server.go), `createListener`, `createWindowsListener`, and `DialWithCertDir`, lines 227, 313, and 474.

Windows always uses a plaintext TCP listener on `127.0.0.1:0`, ignoring the configured TCP address and named pipe. Port zero selects an ephemeral listening port. The default client attempts port zero and requires TLS/certificate loading for Windows connections. It cannot connect successfully using these defaults, and even a discovered port has a TLS/plaintext mismatch.

**Fix:** implement named-pipe server/client transport with explicit access controls, or a consistently configured TLS listener/client. Remove the silent fallback and define native paths for credentials and configuration.

**Acceptance:** on Windows, the installed CLI connects to the installed service using defaults; unauthorized local users are denied and any optional TCP transport verifies server identity.

### R10 — P1: the macOS Endpoint Security build is incomplete

**Reproduced:** `go build -tags esf` fails at [internal/platform/darwin/esf/client.go](internal/platform/darwin/esf/client.go), line 10: `fatal error: 'client.h' file not found`.

Only backup-suffixed C/header files are present. Normal Makefile macOS targets omit the `esf` tag, so their successful builds use the unavailable ES stub. Signing those binaries does not add the missing sensor implementation.

**Fix:** restore a buildable native bridge or replace it with a packaged Endpoint Security extension and a defined daemon transport. Make minimal and sensor-enabled build variants explicit.

**Acceptance:** a native sensor build compiles, signs, installs, and emits real events; an unentitled/minimal build reports its limitation. Test the deployed variant with SIP enabled.

### R11 — P1: failed storage initialization can crash service startup

**Evidence:** [internal/daemon/services.go](internal/daemon/services.go), lines 63–66; [internal/storage/factory/factory.go](internal/storage/factory/factory.go), `New`; [internal/service/threat/service.go](internal/service/threat/service.go), `Start`/`loadCache`, line 306.

An unknown backend or inaccessible storage directory makes the factory return a nil store and an error. Initialization only logs the error and passes that nil store into dependent services. With threat intelligence enabled, startup dereferences it in `loadCache`; patch scans also call the store without a nil check. Startup failure after other services have started lacks comprehensive rollback in the daemon/registry.

**Fix:** fail initialization before registering storage-dependent services, validate backend configuration, and unwind successful starts in reverse order on later failures. Make repeated shutdown safe.

**Acceptance:** invalid backend, denied storage, and occupied IPC port produce clear errors, no panic, and no surviving listeners, goroutines, or plugin processes.

### R12 — P2: configuring application lockdown always deadlocks

**Evidence:** [internal/service/app_lockdown/service.go](internal/service/app_lockdown/service.go), lines 83–109.

`Configure` acquires `s.mu`, then calls `EnableLockdown` or `DisableLockdown`, both of which acquire the same non-reentrant mutex. Any correctly typed configuration hangs. In addition, enablement only sets a flag and logs a blocking claim; it performs no enforcement. The deadlock is a direct source-level finding; no production reconfiguration path was executed.

**Fix:** separate locked state transitions from external operations, report enforcement as unsupported until implemented, and synchronize health reads.

**Acceptance:** configure both states repeatedly with a deadline and race checks. Active enforcement must require successful OS-level application and verification.

### R13 — P2: SIEM batches are discarded after delivery failure

**Evidence:** [internal/service/siem/service.go](internal/service/siem/service.go), lines 123–179.

`flush` returns no delivery status; the caller clears the batch after connection errors or HTTP rejection. Full queues silently drop events. Shutdown flushes the current batch but does not drain the queued events or wait for the worker. Once ingestion is connected, even a brief SIEM outage can permanently erase security evidence while health still says forwarding is active.

**Fix:** acknowledge batches only after accepted delivery, use a bounded durable spool with retry/backoff and event IDs, expose losses, and drain within the shutdown deadline.

**Acceptance:** inject timeouts, 429/500 responses, process restart, and disk-full conditions. Verify replay and deduplication, bounded resource use, and accurate degraded health.

### R14 — P1: tests and release automation cannot validate the advertised builds

**Reproduced:** the native Go test command fails in IPC/plugin vet checks, beacon and memory test compilation, and DNS detector assertions. See the verification table below.

**Evidence:** [internal/ipc/server.go](internal/ipc/server.go), lines 555 and 771, uses `string(health.Status)` on an integer enum, yielding control characters rather than health names. Plugin adapters use dynamic errors as `fmt.Errorf` format strings. Beacon and memory tests refer to outdated signatures/methods. [.github/workflows/ci.yml](.github/workflows/ci.yml), lines 66–75, and [.github/workflows/release.yml](.github/workflows/release.yml) call `make build-all`, which does not exist, and expect `dist/`, while the Makefile writes `bin/`. `make build` currently resolves to the existing `build/` directory without building anything. Workflows specify Go 1.21/1.22 despite the module's Go 1.25.2 requirement; automatic toolchain downloads do not make that an intentional test matrix.

**Fix:** reconcile tests with intended detector behavior, fix real errors rather than disabling vet, align toolchain/build targets/artifact paths, and explicitly test nested modules and native sensor variants.

**Acceptance:** reproducible native CI runs and tagged packaging use the same tested targets. DNS fixtures require a documented scoring interpretation, not merely weaker expectations.

## Verification performed

Host: Darwin x86_64. Used installed Go 1.25.7 via `ASDF_GOLANG_VERSION=1.25.7`; the default asdf shim had no selected Go version. Build-cache access required sandbox escalation. No firewall, package-installation, service-installation, or malware execution commands were run.

| Check | Result |
| --- | --- |
| `go test ./internal/... ./pkg/... ./cmd/afterdark-darkd ./cmd/afterdark-darkdadm` | Failed: IPC health conversions; plugin formatting vet errors; stale beacon and memory test APIs; DNS entropy and tunnel-scoring assertions |
| `go build ./cmd/afterdark-darkd ./cmd/afterdark-darkdadm ./plugins/firewall-linux ./plugins/firewall-macos ./plugins/firewall-windows` | Passed on the macOS host; this verifies compilation, not operation on the plugin's target OS |
| `GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o /tmp/darkd-review-linux ./cmd/afterdark-darkd` | Passed; Linux runtime behavior was not tested |
| `GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -o /tmp/darkd-review-windows.exe ./cmd/afterdark-darkd` | Failed: `syscall.Stat_t` in shared plugin host |
| `go build -tags esf -o /tmp/darkd-review-esf ./cmd/afterdark-darkd` | Failed: missing `client.h` |
| `make -n build` / `make -n build-all` | First reports an existing directory as up to date; second has no target |

The root test command does not cover nested Go modules such as `plugins/osquery` and `plugins/osx-security/*`. No clean race-test result, signed macOS sensor test, Linux runtime test, Windows runtime test, or dependency-vulnerability audit is claimed.

## Platform baseline and next step

| Area | macOS | Linux | Windows |
| --- | --- | --- | --- |
| Daemon compilation | Normal build passes | amd64 cross-build passes | Blocked |
| Native event collection | ES bridge build blocked; handler only logs | eBPF startup is a stub | ETW consumer exists but only logs; daemon blocked |
| Patch assessment | Implemented parser; deadline defect | Placeholder yielding false compliance | Placeholder yielding false compliance |
| Administrative transport | Unix socket and TLS TCP paths exist | Unix socket and TLS TCP paths exist | Defaults incompatible |
| Firewall integration | Plugin exists; host adapter missing | Plugin exists; host adapter and policy defects | Plugin exists; host adapter missing |
| Memory scanning | Reader placeholder | Reader implementation exists; tests stale | Reader implementation exists; tests stale |

Proceed using the [seven-phase enhancement roadmap](ROADMAP.md). Phases 1–2 establish a trustworthy shared foundation; platform-specific depth follows that foundation.
