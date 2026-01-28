# Production Domains Requiring OAuth/SSO

## Overview

**Current Status**: 21 OAuth providers configured for **localhost only**
**Production Domains**: 28 domains requiring OAuth integration
**Gap**: Need to add production redirect URIs and possibly create additional providers

---

## Production Domain Inventory

### 1. Core Infrastructure (*.afterdarksys.com)
- **console.afterdarksys.com** - Management Console ✅ (has localhost provider)
- **auth.afterdarksys.com** - Authentik itself (identity provider)
- **api.afterdarksys.com** - API Gateway
- **darkd.afterdarksys.com** - DarkD Dashboard ✅ (has localhost provider)
- ***.afterdarksys.com** - Wildcard catch-all

### 2. AI/ML Platforms
- **aeims.app** - AI Enterprise Management System
- **promptery.io** - Prompt engineering platform
- **aiserve.farm** - AI service orchestration
- **llmsecurity.dev** - LLM security testing
- **model2go.com** - Model deployment platform
- **petalarm.ai** - Pet monitoring AI
- **basebot.ai** - AI chatbot framework

### 3. Development/API Platforms
- **computeapi.io** - Compute API services
- **systemapi.io** - System API gateway
- **telcocloud.io** - Telecom cloud infrastructure
- **console.darkapi.io** - DarkAPI console ✅ (localhost provider exists as "unified-dashboard")

### 4. Security/Network Tools
- **veribits.com** - Verification & validation platform
- **betterphish.io** - Phishing detection/training
- **filehashes.io** - File hash verification
- **web3dns.io** - Web3 DNS services
- **onedns.io** - DNS management platform

### 5. Business/Marketing
- **viralvisions.io** - Marketing analytics
- **flipdomain.io** - Domain flipping marketplace
- **flipid.io** - Identity verification
- **itz.agency** - IT consulting/agency site
- **shipshack.io** - Shipping/logistics platform
- **afterapps.io** - App marketplace

### 6. Personal/Community
- **purrr.love** - Cat community platform
- **purrr.me** - Personal cat profile site
- **cats.center** - Cat enthusiast hub
- **dogs.institute** - Dog training/education
- **lonely.fyi** - Social connection platform

### 7. Storage/Infrastructure
- **darkstorage.io** - Storage platform

---

## Current OAuth Providers (Localhost Only)

We have **21 providers** configured, but they only have **localhost redirect URIs**:

| Service | Client ID | Localhost Port | Production Domain(s) |
|---------|-----------|----------------|---------------------|
| AfterDark HTTP Proxy | ads-httpproxy-client | 8080 | ❌ No production URIs |
| Management Console | ads-management-console | 9100 | ✅ console.afterdarksys.com |
| DarkD Dashboard | darkd-dashboard-client | 5173 | ✅ darkd.afterdarksys.com |
| DLP GUI | dlp-gui-client | 5174 | ❌ No production URIs |
| Lowkey Flutter UI | lowkey-ui-client | 5175 | ❌ No production URIs |
| Native GUI | native-gui-client | N/A | ❌ No production URIs |
| DarkD API | darkd-api-client | 8081 | ✅ api.afterdarksys.com |
| C2 Framework | c2-api-client | 8082 | ❌ No production URIs |
| Lowkey Server | lowkey-api-client | 8083 | ❌ No production URIs |
| Process Monitor | process-monitor-client | 9001 | ❌ No production URIs |
| Memory Forensics | memory-forensics-client | 9002 | ❌ No production URIs |
| Security Timeline | timeline-api-client | 9012 | ❌ No production URIs |
| PAM | pam-api-client | 9011 | ❌ No production URIs |
| SCFW | scfw-api-client | 9010 | ❌ No production URIs |
| Packet Recorder | packet-recorder-client | 8084 | ❌ No production URIs |
| Log Aggregator | log-aggregator-client | 9014 | ❌ No production URIs |
| Disk Imager | disk-imager-client | 9015 | ❌ No production URIs |
| Unified Dashboard | unified-dashboard-client | 9000 | ✅ console.darkapi.io |
| AI Analytics | ai-analytics-client | 9016 | ❌ No production URIs |
| Network Monitoring | network-monitoring-client | 9017 | ❌ No production URIs |
| Security Suite (general) | afterdark-security-suite | N/A | ✅ *.afterdarksys.com |

---

## What's Left: Production OAuth Setup

### Option 1: Update Existing Providers with Production URIs

For the 21 existing providers, add production redirect URIs:

```python
from adsyslib.authentik import AuthentikOAuthManager

manager = AuthentikOAuthManager()

# Example: Update Management Console for production
# This would require extending adsyslib with update_provider() method
```

**Pros**: Reuses existing providers, maintains localhost dev flow
**Cons**: Need to add update functionality to adsyslib

### Option 2: Create New Providers for Production Domains

Create **28 new OAuth providers** specifically for production domains:

```json
{
  "apps": [
    {
      "app_name": "Viral Visions",
      "app_slug": "viralvisions-io",
      "client_id": "viralvisions-io-client",
      "redirect_uris": [
        "https://viralvisions.io/oauth/callback"
      ],
      "launch_url": "https://viralvisions.io/",
      "client_type": "confidential"
    },
    {
      "app_name": "AEIMS App",
      "app_slug": "aeims-app",
      "client_id": "aeims-app-client",
      "redirect_uris": [
        "https://aeims.app/oauth/callback"
      ],
      "launch_url": "https://aeims.app/",
      "client_type": "confidential"
    }
    // ... 26 more
  ]
}
```

**Pros**: Clean separation between dev and prod
**Cons**: 49 total providers (21 dev + 28 prod)

### Option 3: Hybrid - Shared Providers with Multi-Environment URIs

Update existing providers to include both localhost AND production URIs:

```json
{
  "redirect_uris": [
    "http://localhost:9100/oauth/callback",
    "https://console.afterdarksys.com/oauth/callback"
  ]
}
```

**Pros**: Single provider per service, simpler management
**Cons**: Dev and prod share client secrets (security concern)

---

## Recommended Approach

### Phase 1: Update Existing Providers (Quick Win)

Add production URIs to the existing 21 providers where mappings are clear:

| Existing Provider | Add Production URI |
|-------------------|-------------------|
| ads-management-console | https://console.afterdarksys.com/oauth/callback |
| darkd-dashboard-client | https://darkd.afterdarksys.com/oauth/callback |
| darkd-api-client | https://api.afterdarksys.com/oauth/callback |
| unified-dashboard-client | https://console.darkapi.io/oauth/callback |

### Phase 2: Create Providers for Unmapped Domains

Create **24 new OAuth providers** for domains not mapped to existing services:

1. viralvisions.io
2. aeims.app
3. veribits.com
4. telcocloud.io
5. computeapi.io
6. systemapi.io
7. purrr.love / purrr.me
8. cats.center
9. dogs.institute
10. darkstorage.io
11. shipshack.io
12. promptery.io
13. aiserve.farm
14. lonely.fyi
15. llmsecurity.dev
16. model2go.com
17. flipdomain.io
18. flipid.io
19. petalarm.ai
20. web3dns.io
21. itz.agency
22. onedns.io
23. betterphish.io
24. basebot.ai
25. filehashes.io
26. afterapps.io

### Phase 3: SSL/TLS Setup

All production domains need:
- Valid SSL certificates (Let's Encrypt recommended)
- DNS A/CNAME records pointing to your infrastructure
- Nginx/Traefik reverse proxy configuration
- HTTPS enforcement (HTTP → HTTPS redirect)

### Phase 4: OAuth Middleware Integration

Each service needs:
- OAuth client library installed
- Redirect URI configuration
- Session management
- Token validation
- Protected routes

---

## Domain Categorization by Priority

### Critical (Must Have Auth)
1. **console.afterdarksys.com** - Main admin console
2. **console.darkapi.io** - DarkAPI console
3. **auth.afterdarksys.com** - Authentik itself
4. **api.afterdarksys.com** - API gateway

### High Priority (Business Critical)
5. viralvisions.io
6. aeims.app
7. veribits.com
8. computeapi.io
9. systemapi.io
10. telcocloud.io

### Medium Priority (Active Projects)
11. promptery.io
12. aiserve.farm
13. llmsecurity.dev
14. model2go.com
15. basebot.ai
16. betterphish.io
17. filehashes.io
18. afterapps.io

### Lower Priority (Community/Personal)
19. purrr.love / purrr.me
20. cats.center
21. dogs.institute
22. lonely.fyi
23. darkstorage.io
24. shipshack.io
25. flipdomain.io
26. flipid.io
27. petalarm.ai
28. web3dns.io
29. itz.agency
30. onedns.io

---

## Next Steps

### Immediate Actions

1. **Extend adsyslib** with `update_provider()` method to add redirect URIs
2. **Create production domain config** JSON file with all 28 domains
3. **Verify DNS records** for all domains
4. **Set up SSL certificates** (Let's Encrypt wildcard for *.afterdarksys.com)
5. **Update existing providers** with production URIs (Phase 1)
6. **Create new providers** for unmapped domains (Phase 2)

### Script to Generate Production Config

```python
from adsyslib.authentik import OAuthProviderConfig

domains = [
    ("Viral Visions", "viralvisions.io"),
    ("AEIMS", "aeims.app"),
    ("Veribits", "veribits.com"),
    # ... all 28 domains
]

configs = []
for name, domain in domains:
    slug = domain.replace('.', '-')
    config = OAuthProviderConfig(
        app_name=name,
        app_slug=slug,
        client_id=f"{slug}-client",
        redirect_uris=[f"https://{domain}/oauth/callback"],
        launch_url=f"https://{domain}/",
        client_type="confidential"
    )
    configs.append(config)

# Save to JSON
import json
with open('production_domains.json', 'w') as f:
    json.dump({"apps": [asdict(c) for c in configs]}, f, indent=2)
```

### Bulk Create Command

```bash
# Create all 28 production OAuth providers
adsys authentik oauth-bulk-create \
  production_domains.json \
  --output-env .env.production \
  --output-json production_oauth_secrets.json

# Result: 49 total OAuth providers (21 dev + 28 prod)
```

---

## Security Considerations

### Separate Dev/Prod Credentials
- **Recommended**: Different client secrets for dev vs prod
- Use `.env.development` and `.env.production`
- Never commit production secrets to git

### SSL/TLS Requirements
- All production domains MUST use HTTPS
- HTTP should redirect to HTTPS
- Valid SSL certificates required (no self-signed in prod)

### Redirect URI Validation
- Authentik enforces strict redirect URI matching
- Use `https://` for production
- Consider wildcard URIs for flexibility: `https://*.afterdarksys.com/*`

### Session Management
- Secure cookies (Secure + HttpOnly + SameSite)
- Session timeout configuration
- Logout functionality across all services

---

## Summary

**What's Already Done:**
- ✅ 21 OAuth providers for localhost development
- ✅ CLI tools to manage providers
- ✅ Documentation and examples

**What's Left:**
- ❌ Add production redirect URIs to existing 21 providers
- ❌ Create 24-28 new providers for production domains
- ❌ Set up SSL certificates for all domains
- ❌ Configure DNS for all domains
- ❌ Deploy OAuth middleware in each service
- ❌ Test SSO flow across all domains

**Total OAuth Providers Needed**: 45-49
- 21 existing (localhost)
- 24-28 new (production domains)

**Estimated Effort**:
- Provider creation: 1 hour (using adsyslib bulk create)
- SSL/DNS setup: 2-4 hours (depends on current state)
- OAuth middleware integration: 1-2 hours per service (24-28 services)
- Testing: 2-4 hours

**Total: 30-40 hours of work** to get all domains OAuth-enabled.
