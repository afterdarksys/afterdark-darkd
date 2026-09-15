# Endpoint investigation and detection replay

Darkd can retain process and connection observations locally, show a chronological
timeline, export evidence, and replay versioned detection rules without taking
response actions. This is the first enterprise/research milestone; fleet rule
distribution and automated response are separate work.

Enable collection in `darkd.yaml`, then restart the daemon:

```yaml
services:
  investigation:
    enabled: true
    retention: 168h
    max_events: 100000
    include_command_line: false
```

Collection is disabled by default. The journal lives at
`<daemon.data_dir>/investigation/events.db`. The directory is created with mode
0700 and the database with mode 0600 on Unix. Local file permissions control
administrative access; these commands do not bypass permissions through IPC.
Use OS ACLs to restrict the data directory on Windows. Database access does not
require a running daemon or an external service. Retained evidence remains on
disk when collection is disabled.

```sh
afterdark-darkdadm investigate timeline --limit 100
afterdark-darkdadm investigate timeline --entity PROCESS_ENTITY_ID --json
afterdark-darkdadm investigate export --since 2026-09-13T00:00:00Z > evidence.ndjson
afterdark-darkdadm investigate replay --rules configs/investigation-rules.example.json
afterdark-darkdadm investigate replay --rules configs/investigation-rules.example.json --input evidence.ndjson
```

Use `--db PATH` when the daemon data directory differs from `/var/lib/afterdark`.
Filters include `--endpoint`, `--entity`, `--kind`, `--since`, `--until`, and
`--limit`. Time bounds are inclusive RFC3339 timestamps. The default limit of
zero includes all matches; export and replay stream results instead of loading
the complete journal into memory. Database queries use a consistent read
snapshot, ordered by observation time and insertion sequence. Protect exported
files using your shell's umask or destination directory permissions.

Events carry a schema version, event ID, persistent journal endpoint ID,
observation timestamp, sensor source, kind, process entity ID when known, and
named fields. The journal endpoint ID is generated once and retained in the
database; it is currently separate from cloud enrollment identity. Do not clone
the journal into endpoint images. Moving or deleting it changes identity/history.

The process tracker records newly observed instances, changes to their observed
metadata (including executable changes), and parent identity when available.
Process entity IDs include endpoint, PID, and process start time to
distinguish PID reuse. Unknown start times produce no entity ID; such processes
are observed again on each scan. Connection observations include their owning
process identity when available. `network.disappeared` means the connection was
absent from the next scan, not proof of its exact close time. Process exits are
not inferred from missing observations.

These are polling sensors. Short-lived processes/connections can be missed,
permissions can hide metadata, and this milestone does not add kernel capture,
DNS query events, executable signature verification, or file events. Existing
sensor health now reports unsuccessful scans; investigation service health
reports journal failures and a cumulative failed-batch count. Failed process
records remain eligible for the next scan. Failed connection batches are counted
but are not retried. There is no claim of lossless capture.

Process scans read the connection table once to calculate per-process counts.
Both trackers propagate cancellation to OS collection and report stale scans.

Retention runs on startup and sensor batches, including empty batches. Both age
and row count limits apply. SQLite reuses freed pages; this is a retained-row
budget, not an exact byte quota or secure erasure policy. Stopped daemons do not
expire evidence. Command lines are separately opt-in because arguments can
contain secrets. Settings and data-directory changes require a restart.

Rule files contain `schema_version: 1` and a `rules` array. Each rule requires a
unique `id`, `version`, exact event `kind`, and a nonempty `all` array. Conditions
use named event fields with case-sensitive `equals`, `contains`, or Go regex
matching. Every condition must match; absent fields never match. Unknown rule
properties, fields, operators, invalid regexes, and duplicate IDs are rejected.
Rules are declarative and never run scripts or response actions.

Replay emits NDJSON match records containing event ID, rule ID/version,
description, and the actual field values that satisfied the conditions, followed
by a summary of events scanned, events matched, matches per rule, and the SHA-256
of the exact rule file. The summary
is emitted only after successful completion. Malformed evidence or rules return
a nonzero exit code; discard partial output if that happens. Exported input must
be schema-1 NDJSON with each line smaller than 1 MiB. Match counts measure noise,
not false-positive rates: that requires independently labeled evidence.

Validation commands:

```sh
go test -race ./internal/investigation ./internal/daemon ./cmd/afterdark-darkdadm
# Optional: reads real OS process/connection tables and records into a temp directory.
go test -race -tags integration -timeout 3m ./internal/investigation
```

Next milestones: labeled evaluation datasets, live rule activation with versioned
findings, file/DNS sensor adapters, fleet enrollment identity mapping, and staged
rule deployment with rollback.
