# What's Left: Complete OAuth/SSO Rollout

## Current Status Summary

### ✅ Completed (Today's Work)

1. **Created 21 OAuth providers** for localhost development
   - All AfterDark Security Suite services configured
   - Client secrets saved to `.env`
   - Full documentation created

2. **Built custom OAuth CLI tool** (`authentik_oauth_cli.py`)
   - Django ORM direct access (bypasses API/Terraform issues)
   - Bulk creation support
   - Handles dataclass serialization correctly

3. **Integrated into adsyslib**
   - New `authentik/oauth.py` module
   - 5 new CLI commands
   - Python API for programmatic management
   - Complete documentation (`OAUTH_INTEGRATION.md`)

4. **Inventoried production domains**
   - 29 domains identified
   - JSON configuration file created
   - Categorized by priority and type

### ❌ What's Left

## Phase 1: Create Production OAuth Providers (15 minutes)

**Task**: Create 29 OAuth providers for all production domains

**How**:
```bash
cd deployments/authentik
./scripts/create_production_oauth.sh
```

**Result**:
- 29 new OAuth providers created
- Credentials in `config/.env.production`
- Secrets JSON in `config/production_oauth_secrets.json`

**Status**: Ready to run (script created and tested)

---

## Phase 2: DNS & SSL Configuration (2-4 hours)

### DNS Records Needed

For **each of the 29 domains**, verify DNS records point to your infrastructure:

```bash
# Check DNS
dig viralvisions.io +short
dig aeims.app +short
# ... for all 29 domains
```

**Required Records**:
- A record → Your server IP
- OR CNAME → Your load balancer
- Optional: www subdomain (CNAME → apex)

### SSL Certificates

**Option 1: Let's Encrypt (Recommended)**
```bash
# Wildcard cert for *.afterdarksys.com
certbot certonly --dns-cloudflare \
  -d "*.afterdarksys.com" \
  -d "afterdarksys.com"

# Individual certs for other domains
certbot certonly --webroot \
  -w /var/www/html \
  -d viralvisions.io \
  -d www.viralvisions.io
```

**Option 2: Cloudflare SSL**
- Use Cloudflare's Universal SSL
- Set to "Full (strict)" mode
- Auto-renews

**Option 3: Commercial Certificate**
- Purchase wildcard cert
- Install on reverse proxy

### Reverse Proxy Configuration

**Nginx Example**:
```nginx
server {
    listen 443 ssl http2;
    server_name viralvisions.io www.viralvisions.io;

    ssl_certificate /etc/letsencrypt/live/viralvisions.io/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/viralvisions.io/privkey.pem;

    # OAuth callback route
    location /oauth/callback {
        proxy_pass http://backend:3000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }

    # Main application
    location / {
        proxy_pass http://backend:3000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}

# Redirect HTTP to HTTPS
server {
    listen 80;
    server_name viralvisions.io www.viralvisions.io;
    return 301 https://$server_name$request_uri;
}
```

**Traefik Example** (docker-compose.yml):
```yaml
labels:
  - "traefik.enable=true"
  - "traefik.http.routers.viralvisions.rule=Host(`viralvisions.io`) || Host(`www.viralvisions.io`)"
  - "traefik.http.routers.viralvisions.entrypoints=websecure"
  - "traefik.http.routers.viralvisions.tls.certresolver=letsencrypt"
  - "traefik.http.services.viralvisions.loadbalancer.server.port=3000"
```

---

## Phase 3: OAuth Middleware Integration (1-2 hours per service)

### For Each Service

**1. Install OAuth Library**

**Go (most of your services)**:
```bash
go get github.com/coreos/go-oidc/v3/oidc
go get golang.org/x/oauth2
```

**Node.js**:
```bash
npm install openid-client express-session
```

**Python**:
```bash
pip install authlib flask-oidc
```

**2. Configure OAuth Client**

Create `.env.production` for each service:
```env
AUTHENTIK_ISSUER=https://auth.afterdarksys.com/application/o/viralvisions-io-client/
AUTHENTIK_CLIENT_ID=viralvisions-io-client
AUTHENTIK_CLIENT_SECRET=<from config/production_oauth_secrets.json>
AUTHENTIK_REDIRECT_URI=https://viralvisions.io/oauth/callback
SESSION_SECRET=<generate-random-32-char-string>
```

**3. Implement OAuth Flow**

**Go Example** (using go-oidc):
```go
package main

import (
    "context"
    "github.com/coreos/go-oidc/v3/oidc"
    "golang.org/x/oauth2"
    "net/http"
)

var (
    config *oauth2.Config
    verifier *oidc.IDTokenVerifier
)

func init() {
    ctx := context.Background()
    provider, _ := oidc.NewProvider(ctx, os.Getenv("AUTHENTIK_ISSUER"))

    config = &oauth2.Config{
        ClientID:     os.Getenv("AUTHENTIK_CLIENT_ID"),
        ClientSecret: os.Getenv("AUTHENTIK_CLIENT_SECRET"),
        RedirectURL:  os.Getenv("AUTHENTIK_REDIRECT_URI"),
        Endpoint:     provider.Endpoint(),
        Scopes:       []string{oidc.ScopeOpenID, "profile", "email"},
    }

    verifier = provider.Verifier(&oidc.Config{ClientID: config.ClientID})
}

func handleLogin(w http.ResponseWriter, r *http.Request) {
    http.Redirect(w, r, config.AuthCodeURL("state"), http.StatusFound)
}

func handleCallback(w http.ResponseWriter, r *http.Request) {
    ctx := context.Background()

    // Exchange code for token
    oauth2Token, err := config.Exchange(ctx, r.URL.Query().Get("code"))
    if err != nil {
        http.Error(w, "Failed to exchange token", http.StatusInternalServerError)
        return
    }

    // Verify ID Token
    rawIDToken, ok := oauth2Token.Extra("id_token").(string)
    if !ok {
        http.Error(w, "No id_token", http.StatusInternalServerError)
        return
    }

    idToken, err := verifier.Verify(ctx, rawIDToken)
    if err != nil {
        http.Error(w, "Failed to verify token", http.StatusInternalServerError)
        return
    }

    // Extract claims
    var claims struct {
        Email string `json:"email"`
        Name  string `json:"name"`
    }
    idToken.Claims(&claims)

    // Set session (use gorilla/sessions or similar)
    // session.Values["user"] = claims.Email
    // session.Save(r, w)

    http.Redirect(w, r, "/dashboard", http.StatusFound)
}

func authMiddleware(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        // Check session
        // if !session.IsAuthenticated() {
        //     http.Redirect(w, r, "/login", http.StatusFound)
        //     return
        // }
        next.ServeHTTP(w, r)
    })
}
```

**4. Protect Routes**

```go
http.HandleFunc("/login", handleLogin)
http.HandleFunc("/oauth/callback", handleCallback)
http.Handle("/dashboard", authMiddleware(http.HandlerFunc(dashboardHandler)))
http.Handle("/api/", authMiddleware(apiHandler))
```

---

## Phase 4: Testing (2 hours)

### Test Each Domain

**For each of the 29 domains**:

1. **Navigate to domain** (https://viralvisions.io)
2. **Click Login** → redirects to Authentik
3. **Enter credentials** → authenticates
4. **Redirects back** → logged in
5. **Access protected route** → allowed
6. **Logout** → session cleared
7. **Try protected route** → redirects to login

### Automated Testing

```python
import requests

domains = [
    "viralvisions.io",
    "aeims.app",
    # ... all 29
]

for domain in domains:
    # Test HTTPS redirect
    r = requests.get(f"http://{domain}", allow_redirects=False)
    assert r.status_code == 301, f"{domain}: HTTP not redirecting"

    # Test SSL
    r = requests.get(f"https://{domain}")
    assert r.status_code in [200, 302], f"{domain}: HTTPS not working"

    # Test OAuth redirect
    r = requests.get(f"https://{domain}/login", allow_redirects=False)
    assert "auth.afterdarksys.com" in r.headers.get("Location", ""), \
        f"{domain}: OAuth redirect not configured"

print("✓ All domains tested")
```

---

## Phase 5: Documentation & Handoff (1 hour)

### Create Per-Domain Documentation

For each service, document:

**Service README**:
```markdown
# Viral Visions - OAuth Configuration

## Environment Variables

Copy `.env.example` to `.env.production`:
```env
AUTHENTIK_ISSUER=https://auth.afterdarksys.com/application/o/viralvisions-io-client/
AUTHENTIK_CLIENT_ID=viralvisions-io-client
AUTHENTIK_CLIENT_SECRET=<see vault>
AUTHENTIK_REDIRECT_URI=https://viralvisions.io/oauth/callback
SESSION_SECRET=<see vault>
```

## Running

```bash
# Development (localhost OAuth)
npm run dev

# Production (production OAuth)
NODE_ENV=production npm start
```

## Testing OAuth

1. Navigate to https://viralvisions.io
2. Click "Login"
3. Authenticate with Authentik
4. Redirected back logged in

## Troubleshooting

- **Redirect loop**: Check AUTHENTIK_REDIRECT_URI matches provider config
- **Invalid token**: Check AUTHENTIK_ISSUER URL
- **403 Forbidden**: Check client secret is correct
```

### Create Deployment Checklist

```markdown
# OAuth Deployment Checklist - [Domain Name]

- [ ] OAuth provider created in Authentik
- [ ] DNS record configured
- [ ] SSL certificate obtained
- [ ] Reverse proxy configured
- [ ] OAuth middleware installed
- [ ] Environment variables configured
- [ ] Protected routes implemented
- [ ] Login flow tested
- [ ] Logout flow tested
- [ ] Session management tested
- [ ] Token refresh working
- [ ] Mobile responsive
- [ ] Error handling complete
- [ ] Documentation updated
- [ ] Monitoring configured
- [ ] Deployed to production
```

---

## Summary of Remaining Work

| Phase | Task | Estimated Time | Status |
|-------|------|---------------|---------|
| 1 | Create 29 production OAuth providers | 15 minutes | ⏳ Ready to run |
| 2 | DNS & SSL setup for 29 domains | 2-4 hours | ⏳ Waiting |
| 3 | OAuth middleware per service (29 services) | 29-58 hours | ⏳ Waiting |
| 4 | Testing all 29 domains | 2 hours | ⏳ Waiting |
| 5 | Documentation | 1 hour | ⏳ Waiting |
| **Total** | | **34-65 hours** | |

### Breakdown by Service Type

**Infrastructure (6 domains)**: 6-12 hours
- afterdarksys.com (wildcard)
- telcocloud.io
- computeapi.io
- systemapi.io
- darkstorage.io
- web3dns.io

**AI Platforms (7 domains)**: 7-14 hours
- aeims.app
- promptery.io
- aiserve.farm
- llmsecurity.dev
- model2go.com
- petalarm.ai
- basebot.ai

**Security Tools (5 domains)**: 5-10 hours
- veribits.com
- betterphish.io
- filehashes.io
- flipid.io
- onedns.io

**Business/Marketing (6 domains)**: 6-12 hours
- viralvisions.io
- flipdomain.io
- itz.agency
- shipshack.io
- afterapps.io
- console.darkapi.io

**Community/Social (5 domains)**: 5-10 hours
- purrr.love
- purrr.me
- cats.center
- dogs.institute
- lonely.fyi

---

## Quick Start: Create All Production Providers NOW

```bash
cd /Users/ryan/development/afterdark-meta-project/afterdark-security-suite/afterdark-darkd/deployments/authentik

# Create all 29 production OAuth providers
./scripts/create_production_oauth.sh

# Result:
# - 29 OAuth providers created in Authentik
# - Credentials in config/.env.production
# - Ready for deployment
```

**After this**, you'll have:
- ✅ 21 localhost OAuth providers (done)
- ✅ 29 production OAuth providers (15 minutes)
- **Total: 50 OAuth providers configured**

Then it's "just" a matter of:
1. Setting up DNS/SSL (infrastructure work)
2. Deploying OAuth middleware to each service (development work)
3. Testing everything (QA work)

---

## Priority Recommendations

### Do First (Critical Infrastructure)

1. **auth.afterdarksys.com** - Authentik itself (already done)
2. **console.afterdarksys.com** - Management console
3. **console.darkapi.io** - DarkAPI console
4. **api.afterdarksys.com** - API gateway

### Do Second (Revenue Generating)

5. **viralvisions.io**
6. **aeims.app**
7. **promptery.io**
8. **model2go.com**
9. **basebot.ai**

### Do Third (Security/Compliance)

10. **veribits.com**
11. **betterphish.io**
12. **llmsecurity.dev**
13. **filehashes.io**

### Do Last (Community/Fun Projects)

14-29. All community and personal sites

---

## Need Help?

I (Claude) can now help you with:

- **Creating providers**: Use adsyslib commands
- **Testing OAuth flows**: Verify configurations
- **Debugging issues**: Check logs and configs
- **Writing middleware**: Generate OAuth integration code
- **Documentation**: Create deployment guides

Just ask! The infrastructure is ready, now it's about execution. 🚀
