# Nine-commit platform enhancement series

This series implements the first working slices of the seven-phase [roadmap](ROADMAP.md). It does not mark the full roadmap complete. The [code review](CODE_REVIEW.md) remains a historical record of the starting commit.

## Commits

| # | Commit | Delivered |
| --- | --- | --- |
| 1 | `afe9212` | Detector regression baseline, PE offset bounds, YARA rule splitting, review and seven-phase roadmap |
| 2 | `f06c487` | Honest unsupported RPCs, health aggregation, startup rollback, idempotent daemon stop, lockdown deadlock mitigation |
| 3 | `9c60a78` | Persisted patch first-observed deadlines, unknown compliance, DNS append/rotation handling |
| 4 | `de5acb1` | SQLite event store, process/network/DNS detection events, durable SIEM retry and event queries |
| 5 | `d25c075` | Buildable macOS Endpoint Security notification bridge and bounded callback queue |
| 6 | `e1e9129` | Linux exec tracepoint eBPF program, APT/DNF assessment and package inventory |
| 7 | `bfbe3d2` | Windows service readiness/stop, ACL-restricted named pipes, ETW delivery, Windows Update assessment |
| 8 | `e1acb22` | Firewall host/SDK adapter, actual interface negotiation, trusted launch-path validation and error propagation |
| 9 | This commit | DarkAPI account/device integration, durable cloud export, real CLI results, platform build/CI gates and deployment documentation |

## Implemented scope and remaining work

| Roadmap phase | Implemented in this series | Still needed before the phase exits |
| --- | --- | --- |
| 1: Reliable core | Regression fixes; unsupported errors; startup unwind; persisted deadlines; build gates | Complete capability schema; broader lifecycle tests; safe hot reload; web API authentication and remaining configuration validation |
| 2: Shared events | Versioned envelope, daemon-session ID, durable bounded outbox, process/connection/DNS callbacks, beacon analysis, event queries and acknowledged export | OS boot identity and PID-reuse model; full replay corpus; independent export cursors; corruption/disk-pressure recovery; end-to-end performance qualification |
| 3: macOS | Real ES notification subscription for exec/fork/exit/write/unlink; copied native fields; bounded queue and loss metric; explicit unavailable memory reads | Signed/notarized deployment, app/system-extension packaging, permission/reconnection/sequence-gap testing, native posture and Network Extension work |
| 4: Linux | Real exec tracepoint/perf-buffer collector; PID/UID/comm/time; loss reporting; dpkg/rpm inventory; APT simulation/DNF cached assessment | Native kernel/verifier tests; process-exit/network/file events; container identity; fallback collectors; advisory metadata and packages |
| 5: Windows | Cross-platform builds; SCM readiness and bounded stop; secure pipe dialing; credential ACLs; ETW event ingestion; WUA assessment; service-install scaffold | Native SCM/ETW/WUA tests, unprivileged denial tests, Event Log subscriptions, posture/persistence coverage, signed installer and upgrade/uninstall |
| 6: Response | Firewall interface available to host; deadline/cancellation-aware adapter; real SDK subprocess negotiation test; launch-path ownership/ACL checks | Authorized response service, verified kernel state, timed persistent rollback, quarantine/restore, action audit and IPC wiring. Default-deny is rejected by the host adapter |
| 7: Qualification | Go-version-file CI, native core/race jobs, explicit nested modules, six OS/architecture portable builds, separate native ES build, checksums and draft release | Signed packages, native integration results, GUI/packet-capture variant gates, SBOM/dependency scanning, performance budgets, 24-hour soak and pilot rollout |

The ES bridge currently runs inside the daemon rather than a fully packaged system extension. Linux eBPF uses a small Go-assembled tracepoint program with no kernel-structure offsets; it is not the full CO-RE sensor suite proposed in the roadmap. Windows arm64 artifacts are compile targets, not qualified runtime support.

## Build and verification

```sh
make test         # Core packages; no GUI system-library requirement
make test-race
make vet
make build        # Native daemon, administration CLI, DarkAPI CLI in dist/
make build-all    # All three commands, linux/darwin/windows × amd64/arm64
make native-es    # Native macOS SDK required; output dist/afterdark-darkd-es
```

This workspace uses `ASDF_GOLANG_VERSION=1.25.7` for the commands above. `go.mod` is the CI toolchain source. Portable macOS builds do not include the ES bridge. Building a binary does not qualify runtime sensor access.

CI tests root firewall/ClamAV packages separately and enumerates osquery plus all six macOS plugin modules. The native macOS directory-audit module's missing plist dependency was repaired. GUI and packet-capture variants still need their own system dependencies and validation.

Local validation on macOS Intel with Go 1.25.7:

- Core test/race suite and `go vet`: passed.
- DarkAPI contract, CLI missing-auth, and durable rejection/restart/replay tests: passed.
- All 18 portable daemon/CLI artifacts across six targets: built.
- Native Endpoint Security variant: built with the macOS SDK.
- Root firewall/ClamAV packages and all seven nested modules: passed (many packages have no tests).
- Windows named-pipe integration test: cross-compiled; not executed locally.
- Native CLI help/version smoke checks: passed.

Linux kernel attachment, Windows service/ETW/WUA behavior, signed ES runtime access, the PowerShell installer and Docker image were not executed in this workspace. Release assets are separate platform archives with checksums to avoid filename collisions. Releases remain drafts; Docker publication additionally requires the repository variable `PUBLISH_DOCKER_IMAGES=true`. Generated artifacts in `dist/` are ignored by Git. GitHub CI has been configured but has not been run from this local workspace.

## Deployment boundaries

- See [DarkAPI integration](DARKAPI_INTEGRATION.md) for authentication, enrollment and cloud export.
- [Windows installation scaffold](deployments/windows/install.ps1) registers a service from reviewed configuration and built binaries; start with the [Windows lab configuration](deployments/windows/darkd.yaml.example), secures Program Files/ProgramData directories, and configures Event Log/recovery settings. It does not automatically start the service, implement upgrades, or sign binaries. Validate it on the Windows lab matrix before distributing it.
- Do not label an unavailable sensor as active protection. Default macOS/Linux builds can report degraded capabilities; enabling a native sensor requires its actual privileges and runtime support.
- Firewall adapter negotiation is tested using a harmless subprocess fixture. Real firewall changes, management-traffic preservation and rollback have not been qualified. The legacy backend implementations still need reconciliation and response-policy work.
- Some lifecycle/response RPCs intentionally remain `Unimplemented`. The CLI now exposes those errors instead of invented success.
