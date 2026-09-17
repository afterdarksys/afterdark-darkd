# Ecosystem API clients

`darkapi integrations` exposes five explicit operations. Provider credentials come
only from the indicated environment variable; they are not copied from DarkAPI
credentials. Results remain provider JSON, never a locally invented clean verdict.

| Command | Server contract | Credential |
|---|---|---|
| `darkapi integrations dnsscience example.com` | POST `/api/v1/enrich/domain`, `{domain}` | `DNSSCIENCE_API_KEY`, X-API-Key |
| `darkapi integrations veribits example.com` | POST `/api/v1/dns/check`, `{domain,check_type:"records"}` | `VERIBITS_TOKEN`, Bearer JWT |
| `darkapi integrations systemapi` | GET `/api/v1/fleet` | `SYSTEMAPI_API_KEY`, X-API-Key |
| `darkapi integrations computeapi` | GET `/api/v2/dbaas/instances` | `COMPUTEAPI_API_KEY`, X-API-Key |
| `darkapi integrations planetapi 192.0.2.1` | GET `/v1/ip-blacklist/{ip}` | `PLANETAPI_API_KEY`, X-API-Key |

Use `--endpoint https://staging.example` to select a provider origin, and
`--request-timeout 30s` to bound the request. TLS is required except literal
loopback test addresses. Redirects are rejected to avoid credential forwarding;
responses are capped at 4 MiB. There are no implicit retries, resource creation,
workflow execution, uploads or background telemetry. Targets leave the host only
when the operator invokes a query. DNSScience enrichment may start provider work.

Contracts were checked against local provider source on 2026-09-17:

- dnsscience `god/api/rest/server.go` and `god/api/service.go`.
- veribits.com `app/src/Controllers/DNSCheckController.php` and `Utils/Auth.php`.
  The controller requires a Bearer JWT despite OpenAPI advertising API-key auth.
- systemapi.io `server.js`, `/api/v1/fleet` handler.
- computeapi.io `cmd/api/main.go`, `internal/api/routes/routes.go`, DBaaS handler.
- planetapi.ai `api/main.py`, IP blacklist handler.

Tests exercise exact requests and auth headers, credential-safe errors, HTTP
failures, malformed/oversized responses, redirects and cancellation using local
HTTP fixtures. They are not evidence of deployed provider compatibility.

Provider-side acceptance gaps found during contract review: PlanetAPI's local
source accepts any nonempty key; SystemAPI's fleet handler returns an empty list
on database failure and queries hosts without an organization filter. Do not
interpret either behavior as successful tenant-scoped management. Those provider
services require separate fixes and deployed acceptance before production use.
No production API credentials or live provider acceptance were available here.
