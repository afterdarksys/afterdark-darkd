# Detection and integration review — September 16, 2026

## Delivered in this change

- Explicit server/desktop defaults for Linux, macOS and Windows, with legacy
  configuration compatibility and operator overrides. See `DEPLOYMENT_MODES.md`.
- Real TCP listening-socket drift observations replace the network-drift stub.
  Queue or collection failures preserve the last successful baseline.
- Six versioned investigation rules cover platform-specific review signals.
- Coverage telemetry includes the deployment mode.
- DarkAPI's product page points to the canonical Git repository. Its nested
  `darkd` agent remains a distinct browser-extension collector, not a source mirror.

## Next priorities

| Priority | Enhancement | Acceptance evidence |
| --- | --- | --- |
| 1 | Native sensor validation on each OS | Signed macOS Endpoint Security execution, Linux kernel matrix, Windows ETW/registry/named-pipe runtime tests; unavailable sensors must report degraded coverage |
| 2 | Independent DarkAPI and external SIEM consumers | Separate durable cursors, retry budgets and acknowledgements; an outage of either destination must not lose or block the other stream |
| 3 | Stronger event identity and normalization | Native process start identity, canonical device ID, source version and evidence provenance survive ingestion, replay and cross-agent correlation |
| 4 | Continuous rule execution | Versioned rules consume a durable cursor, preserve evidence IDs, deduplicate alerts and report rule errors; replay remains reproducible |
| 5 | Broader network evidence | Explicit DNS sensor coverage, UDP listeners and firewall policy snapshots; distinguish local binding from measured remote reachability |
| 6 | Persistent listener history | Bounded persisted baselines across restarts, PID reuse handling and suppression controls; no startup alert flood |
| 7 | Consolidate extension inventory | Port the backend's separate browser-extension collector only after fixture-based parity tests and enrollment/schema migration tests |

## Current boundaries

`internal/daemon/config.go` rejects simultaneous DarkAPI and SIEM queue consumers;
independent delivery cursors are required before relaxing that guard.
`internal/service/network_drift/service.go` polls TCP only and resets its baseline
on restart. A partially delivered batch can be repeated. Investigation replay is
explicit; the new pack does not create an automatic remediation pipeline.

Cloud-metadata enforcement, device control, DLP, activity monitoring and ML training
are not made complete by enabling a profile. Their placeholder services are off
in both new profiles. Sensor selection is not proof of native runtime support.
Automatic patch installation, command-line capture and remote administration stay
opt-in. Shared device IDs link evidence; they do not alone prove an anomaly.

## Validation

Go suite and focused race tests passed on the development host. Linux and Windows
CLI cross-builds passed with CGO disabled. Profile tests cover both modes on all
three target OSes, configuration precedence and explicit settings. Listener tests
cover initial baselines, changes, collection failure, queue failure and retry.
Each investigation rule has positive and missing-evidence cases.

Cross-builds do not replace native privileged sensor acceptance testing. The
website changes require deployment before becoming visible in production.
