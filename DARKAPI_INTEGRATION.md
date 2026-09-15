# DarkAPI integration

## Contract used

This implementation follows the handlers in the sibling `darkapi.io` checkout, examined at commit `6d5bd45f518e52ad3f4a145845ba091022e631b7` on 2026-09-15:

- `api/app.py`: password login, account lookup, accessible feeds and paginated feed entries.
- `api/agent_routes.py`: device enrollment, heartbeat, configuration, and durable telemetry acceptance.
- `api/repscore_routes.py`: single and bulk reputation lookup.
- `api/deps.py`: account API-key authentication.
- `k8s/ingress.yaml`: the dedicated API hostname.

These are source-based contract tests against local HTTP fixtures, not a claim that the production deployment has been exercised. No live account was enrolled or production telemetry submitted during development. That initial implementation used the server repository as a read-only reference. A subsequent console enhancement adds single-use enrollment tokens and tenant-scoped telemetry views in the server repository.

## Connect and authenticate

Build with `make build`. Binaries are written to `dist/`.

Default endpoint: `https://api.darkapi.io`. The configuration alias `https://darkapi.io/api/` resolves to the dedicated API hostname because the checked-in ingress serves the web dashboard on the apex hostname. A custom HTTPS origin, with an optional `/api` prefix, is supported. Credentials are bound to the endpoint recorded in their file; changing hosts requires credentials explicitly configured for that host.

```sh
# Reachability is distinct from successful authentication.
dist/darkapi health

# Interactive password prompt; the password is not a command-line argument.
dist/darkapi auth login --email user@example.com
dist/darkapi auth status

# Or supply an existing account key through DARKAPI_API_KEY.
# For automation, DARKAPI_PASSWORD supplies the login password.
# DARKAPI_URL and DARKAPI_CREDENTIAL_FILE override the corresponding defaults.
```

Login stores the returned account key in the OS user-config directory, under `afterdark/darkapi.json`. Override the location with `--credentials`. Files are written by atomic replacement, with mode 0600 on POSIX or a protected Windows ACL for the current user, SYSTEM and Administrators. Keys/passwords are not printed by login or enrollment. HTTP error bodies are omitted from errors to avoid echoing secrets. HTTPS verification is enabled and redirects are rejected.

The server issues expiring console credentials on password login; there is no implemented refresh-token contract. A rejected/expired key produces an error. Authenticate again or use an appropriately provisioned account API key for unattended access.

## Enroll and interact

Enroll with a single-use token created in **Console → Darkd endpoints**, or with an account key carrying `write` or `admin` permission. Set `DARKAPI_ENROLLMENT_TOKEN` to the console token before running `darkapi device enroll`; the token is used only for enrollment and is not stored as an account key. Console tokens expire after 24 hours and can enroll one device. The returned device key has a different scope and is kept separately from the account key.

```sh
dist/darkapi device enroll
dist/darkapi device heartbeat
dist/darkapi device config

dist/darkapi check domain example.com
dist/darkapi check ip 192.0.2.1
dist/darkapi check bulk example.com 192.0.2.1

# Other account-authenticated endpoints, with optional --file request.json:
dist/darkapi request GET /v1/stats
```

Bulk reputation access depends on the account tier. The generic request command supports GET/POST/PUT/PATCH/DELETE for `/v1/` account routes; it does not substitute account credentials for separately scoped firewall-app or device credentials. Remote device configuration is fetched for inspection and is not automatically applied as local policy.

| Operation | Method and server route | Authentication |
| --- | --- | --- |
| Login | POST `/v1/auth/login` | Email/password JSON |
| Account | GET `/v1/account` | `X-API-Key`: account key |
| Enrollment | POST `/v1/devices/enroll` | `enrollment_token`: console token or write-enabled account key |
| Heartbeat | POST `/v1/devices/heartbeat` | Device key plus `X-Device-ID` |
| Device configuration | GET `/v1/devices/config` | Device key plus `X-Device-ID` |
| Telemetry | POST `/api/v1/darkd/telemetry` | Device key; enrolled ID in `system_id` |
| Reputation | POST `/v1/reputation/lookup` | Account key; `{indicator,type}` |
| Bulk reputation | POST `/v1/reputation/lookup/bulk` | Account key; `{indicators:[...]}` |
| Threat feeds | GET `/v1/feeds`, `/v1/feeds/{name}` | Account key; accessible feeds only |

A telemetry file needs a UUID `event_id` retained across retries. The client supplies the enrolled device ID; a conflicting `system_id` is rejected.

```json
{
  "event_id": "b7ad5c3a-d1b1-43f1-b350-d7be39b16a0f",
  "hostname": "lab-host",
  "os_family": "linux",
  "software_catalog": []
}
```

```sh
dist/darkapi device telemetry --file telemetry.json
```

## Enable daemon export

Enroll using a credential file readable by the daemon account. On Windows, store it under the secured ProgramData directory created by the installation scaffold, and run enrollment as an administrator. Give the daemon the absolute path:

```yaml
api:
  darkapi:
    url: https://api.darkapi.io
    api_key: ${DARKAPI_API_KEY}  # Optional override for account/feed access
    credential_file: ${DARKAPI_CREDENTIAL_FILE}
    telemetry_enabled: true
    timeout: 30s
services:
  siem:
    enabled: false
```

Set `DARKAPI_CREDENTIAL_FILE` to the enrolled file before starting the daemon, or place its absolute path in YAML. The daemon's YAML loader expands these environment variables. A device-only file enables telemetry; feed access still needs an account key.

The exporter sends a heartbeat approximately once a minute and sends each persisted event with its original UUID. Only an acknowledgement containing `success: true`, `status: accepted`, and the matching event ID releases the local record. Failure/restart preserves pending records. Delivery is at least once; the server deduplicates `(device_id,event_id)`. Patch inventory is published into the same event pipeline instead of being sent to the unrelated AfterDark API with a fabricated system ID.

The current outbox has one delivery acknowledgement per event. Configuration therefore permits **either DarkAPI export or generic SIEM export**, until independent destination cursors are implemented. The store bounds records at 10,000 and each event at 64 KiB; full unacknowledged storage rejects new events and degrades health. Long-term archive retention and disk-pressure recovery remain roadmap work.

Threat sync downloads a bounded snapshot of accessible feeds (100 feeds / 100,000 entries maximum). Failed, inaccessible or oversized snapshots do not advance the last-successful-sync time. Missing feed entries mean no match in the available snapshot, not proof of safety. Server pagination is offset-based, so a changing feed does not provide transactional snapshot isolation.

## Tests

`make test-race` includes API contract fixtures for authentication, enrollment, key scopes, endpoint prefixes, redirect rejection, failure sanitization, cancellation, reputation/feed payloads, and telemetry acknowledgement. The exporter test closes and reopens the SQLite store between rejection and successful delivery. Native Windows ACL and pipe behavior additionally requires the Windows CI job.
