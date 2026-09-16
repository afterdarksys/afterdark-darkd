# Endpoint operations: collector coverage, baselines and response

## Rollout

Apply DarkAPI migration `20260917_endpoint_operations.sql` before deploying the
API, console and `endpoint-analysis` worker from the same revision. Upgrade both
clients afterward. This source change does not deploy production services.
Existing enrollment/device IDs remain unchanged; credentials are app-specific.

In the console, select a host under **Endpoints → Endpoint operations**:

- **Coverage:** inspect each app/sensor independently. Missing, stale, unsupported
  and permission-denied observations must never be interpreted as protection.
  Missing counters mean unknown, not zero. Delivery canaries show server receipt
  versus observation time; clock skew affects that interval.
- **Baselines:** observe warm-up and model status. Default is 30 observations and
  24 hours; execution-hour novelty additionally requires seven days of history.
  Configure the host role before interpreting role/OS peers.
- **Incidents:** investigate the retained timeline, assign an operator label,
  update status with a note, review individual detections and record feedback.
  Assignment labels do not grant permissions. Grouping uses the host and a
  six-hour observation window; it does not assert causality.
- **Response & policy:** enable only needed diagnostic actions, set maintenance
  windows, opt into raw-evidence archival/expiry, and inspect the audit trail.

## Supported response operations

All actions are disabled by default. A write-authorized owner must enable the
specific action. The target app must report fresh support (within three minutes).
Requests carry an idempotency UUID and expire after 30–900 seconds. Agents obtain
60-second leases; stale leases cannot acknowledge success. Results are durably
recorded locally before acknowledgment, so retries reuse the same result.

| Action | darkd | Aftersec |
| --- | --- | --- |
| `collect_status` | Service health snapshot | Queue/delivery statistics |
| `delivery_canary` | Durable telemetry canary | Durable telemetry canary |
| `list_persistence` | Unsupported | Bounded system entry names on macOS/Linux |

There is no shell execution, host isolation, process termination or destructive
remediation in this allowlist. SOAR requires an explicit owner-scoped mapping from
an existing active legacy agent ID to the host/app. It then uses the same policy,
capability, expiry and acknowledgment checks. Unlinked legacy workflows retain
existing behavior. Suppressed detections remain recorded and do not trigger the
endpoint detection topic's SOAR workflow.

## Credential rotation

On the enrolled host, with its private credential file:

```
aftersec cloud rotate --credentials /secure/path/aftersec-darkapi.json
darkapi device rotate --credentials /secure/path/darkd-darkapi.json
```

Restart the corresponding daemon after success. The sibling application's key is
unchanged. The CLI durably writes a private `.rotation` file before confirming the
new key. Rerun the same command after an interruption; it resumes confirmation.
An expired unconfirmed rotation can be restarted only after the old key still
authenticates. Never delete a pending file merely because the network is offline.
Use a private parent directory. POSIX files are mode 0600; Windows files restrict
access to the current user, SYSTEM and Administrators and use write-through rename.

## Collection and platform capability matrix

| Capability | macOS | Linux | Modern Windows framework |
| --- | --- | --- | --- |
| Firewall snapshot | Application Firewall global state; not PF | UFW state, or bounded nftables ruleset | ActiveStore Domain/Private/Public profiles |
| Firewall enforcement claim | Explicit global state only | UFW explicit state; nftables rules do not prove enforcement | All three effective profile states must parse |
| Patch installation history | Bounded install.log tail | dpkg/dnf installation log tail | Explicitly unsupported |
| Reboot-required state | Unknown | Debian reboot-required marker when applicable | Unknown |
| Sensor health/freshness | Supported | Supported | Portable reporting contract |
| Native process/network/FIM/HIDS | Existing collectors and actual events | Existing collectors and actual events | Existing app capabilities only; no new native sensor parity claim |
| Read-only response | See action table | See action table | Portable status/canary framework; Aftersec native daemon dependencies remain separate |

Native command output is limited to 8 KiB with a five-second deadline. Failed or
unavailable collection does not invent facts. Firewall snapshots include a digest
for comparing rule changes; they describe the queried component, not every
possible enforcement layer. Installation logs are not patch-compliance proof.

Darkd now forwards integrity hash changes, persistence inventory observations and
canary modifications. Persistence discovery on the first scan is inventory, not a
claim that an attacker just installed persistence. File and canary events do not
invent process attribution. Aftersec vulnerability findings carry package/version
and an explicit vulnerable fact. HIDS rule versions, parent identities and action
outcomes remain unknown when the producing collector does not supply them; raw
source evidence is retained. `auth_exec` is an authorization request, not proof of
execution. PID-only reports cannot prove cross-app process identity.

Aftersec reports imported sensor observations and process-lifetime source write
attempts, durable journal writes and write errors. A failed SQL projection after a
successful journal append is recoverable and is not counted as a lost observation.
Kernel or producer drops before these boundaries remain unknown unless reported.

## Baseline interpretation and limits

Model `endpoint-baseline-v1` evaluates executable/parent lineage novelty,
destination and DNS novelty, execution-hour changes, robust outbound-volume
outliers, privilege changes, and regular connection intervals. Novelty can be
explained by at least three same-owner/role/OS peers. Same-host/feature/second
observations from both apps count once. Maintenance observations are excluded
from training/scoring; invalid clocks and insufficient history prevent scoring.

Each evaluation examines at most 5,000 prior host events over 30 days and 1,000
peer events. Truncated host history is explicitly `incomplete_history`; it does
not silently produce a confident result. This is a bounded initial model, not a
trained fleet-scale streaming model. Reviewed dispositions are grouped by rule
version; reviewed false alarms are not a population-wide false-positive rate.
Versioned replay uses the currently retained history and does not erase prior
findings or analyst decisions. There is no automatic remediation from anomaly
scores. DNS novelty does not establish DNS tunneling, and periodic traffic can be
legitimate scheduled work.

## Retention and capacity

Archival/expiry is opt-in. Default policy: archive after 30 days, expire after
365 days, live quota 100,000 events. The worker archives normalized/analyzed raw
payloads as compressed database blobs with SHA-256 integrity checks. Original
payload retries remain idempotent after archival. Open/investigating incidents pin
their evidence archives. Expired archives retain an explicit unavailable status.
Raw-event metadata, normalized fields, projected engine records, command receipts
and audit history are not deleted by this raw-payload policy. This is not complete
personal-data erasure or an external cold-storage service. Capacity rejection is
retryable; agents retain their queues. Monitor backlog and provision database
storage before increasing limits. Initial command queue cap is 100 active requests
per host; local command receipts are retained for durable retry deduplication.

## Production acceptance

Use a dedicated enrolled host for each supported OS. Verify enrollment, paired
DeviceID, a real sensor event, canary receipt, coverage freshness, an approved
status command, lease retry, key rotation followed by daemon restart, and outage
recovery. Exercise denied permissions and disabled sensors. Native Windows
execution and Linux/macOS privileged sensor behavior require platform runners;
cross-compilation and command-output fixtures alone do not establish runtime
compatibility. The repository CI matrix exercises portable collector fixtures on
all three operating systems. Do not enable destructive actions based on these
initial diagnostic capabilities.
