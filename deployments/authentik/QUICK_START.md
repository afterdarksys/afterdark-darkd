# OAuth Deployment - Quick Start Guide

## TL;DR

You have **29 services** that need OAuth deployed by **February 2, 2026**.

All credentials are generated. All .env files are ready. Templates are provided.

---

## What's Ready ✅

1. **50 OAuth providers** created in Authentik (21 localhost + 29 production)
2. **29 .env.production files** in `config/services/*/` with all credentials
3. **OAuth middleware templates** for Go, Node.js, Python in `OAUTH_MIDDLEWARE_TEMPLATE.md`
4. **Deployment helper scripts** in `config/deploy_env_files.sh`

---

## Deploy One Service (5 Minutes)

### Example: viralvisions.io

```bash
# 1. Copy .env to service directory
cp config/services/viralvisions-io/.env.production ~/projects/viralvisions/.env.production

# 2. Add OAuth code (see OAUTH_MIDDLEWARE_TEMPLATE.md)
cd ~/projects/viralvisions
# Copy oauth.go from template
# Update main.go with OAuth routes

# 3. Install dependencies
go get github.com/coreos/go-oidc/v3/oidc
go get golang.org/x/oauth2
go get github.com/gorilla/sessions
go get github.com/joho/godotenv
go mod tidy

# 4. Build and deploy
docker-compose down
docker-compose up -d --build

# 5. Test
curl -I https://viralvisions.io/login
# Should redirect to auth.afterdarksys.com

# 6. Manual test
open https://viralvisions.io/
# Click login → authenticate → should redirect back logged in
```

---

## Deploy All Services (Bulk)

### Method 1: Manual Loop

```bash
# Edit this list with your service paths
SERVICES=(
  "viralvisions-io:/home/deploy/viralvisions"
  "aeims-app:/home/deploy/aeims"
  "veribits-com:/home/deploy/veribits"
  # ... add all 29
)

for entry in "${SERVICES[@]}"; do
  IFS=':' read -r service path <<< "$entry"
  echo "📦 Deploying $service..."

  # Copy .env
  cp config/services/$service/.env.production $path/.env.production

  # Deploy (adjust command for your setup)
  cd $path
  docker-compose up -d --build

  echo "✅ $service deployed"
done
```

### Method 2: Remote Deployment

```bash
# If services are on remote servers
for entry in "${SERVICES[@]}"; do
  IFS=':' read -r service domain <<< "$entry"

  echo "🚀 Deploying to $domain..."

  # Copy .env
  scp config/services/$service/.env.production deploy@$domain:/app/.env.production

  # Deploy
  ssh deploy@$domain "cd /app && docker-compose up -d --build"

  # Test
  curl -I https://$domain/login | grep -q "auth.afterdarksys.com" && echo "✅" || echo "❌"
done
```

---

## Files You Need

### For Each Service

1. **`.env.production`** - Located in `config/services/[service-slug]/.env.production`
   - Contains: AUTHENTIK_CLIENT_ID, AUTHENTIK_CLIENT_SECRET, SESSION_SECRET
   - Copy to service root directory

2. **OAuth middleware code** - Templates in `OAUTH_MIDDLEWARE_TEMPLATE.md`
   - Go: Copy `oauth.go`, update `main.go`
   - Node.js: Copy `oauth.js`, update `server.js`
   - Python: Add OAuth to `app.py`

---

## 29 Services List

### Copy-Paste Ready

```
viralvisions-io       → viralvisions.io
aeims-app             → aeims.app
veribits-com          → veribits.com
afterdarksys-com      → afterdarksys.com
telcocloud-io         → telcocloud.io
computeapi-io         → computeapi.io
systemapi-io          → systemapi.io
purrr-love            → purrr.love
purrr-me              → purrr.me
cats-center           → cats.center
dogs-institute        → dogs.institute
darkstorage-io        → darkstorage.io
shipshack-io          → shipshack.io
console-darkapi-io    → console.darkapi.io
promptery-io          → promptery.io
aiserve-farm          → aiserve.farm
lonely-fyi            → lonely.fyi
llmsecurity-dev       → llmsecurity.dev
model2go-com          → model2go.com
flipdomain-io         → flipdomain.io
flipid-io             → flipid.io
petalarm-ai           → petalarm.ai
web3dns-io            → web3dns.io
itz-agency            → itz.agency
onedns-io             → onedns.io
betterphish-io        → betterphish.io
basebot-ai            → basebot.ai
filehashes-io         → filehashes.io
afterapps-io          → afterapps.io
```

---

## Test One Service

```bash
#!/bin/bash
DOMAIN="viralvisions.io"

echo "Testing $DOMAIN..."

# 1. Home page loads
curl -s -o /dev/null -w "Home: %{http_code}\n" "https://$DOMAIN"

# 2. Login redirects to Authentik
LOCATION=$(curl -sI "https://$DOMAIN/login" | grep -i location | awk '{print $2}')
echo "Login redirect: $LOCATION"

# 3. OAuth callback exists
curl -s -o /dev/null -w "Callback: %{http_code}\n" "https://$DOMAIN/oauth/callback"

# 4. Protected route redirects
curl -sI "https://$DOMAIN/dashboard" | grep -i location
```

---

## Common Issues

### 1. Environment variables not loaded
```bash
# Check if .env.production is in correct location
ls -la .env.production

# For Go: ensure godotenv loads it
godotenv.Load(".env.production")

# For Node.js: ensure dotenv loads it
require('dotenv').config({ path: '.env.production' })

# For Python: ensure python-dotenv loads it
load_dotenv('.env.production')
```

### 2. Redirect URI mismatch
```bash
# Check .env has correct URI
grep REDIRECT_URI .env.production

# Should be: https://[domain]/oauth/callback
# NOT: http:// or localhost
```

### 3. Client secret wrong
```bash
# Double-check secret from config file
cat config/services/[service]/.env.production | grep CLIENT_SECRET

# Should be 128 character alphanumeric string
```

### 4. Session not persisting
```bash
# Check SESSION_SECRET is set
grep SESSION_SECRET .env.production

# Check cookies are secure
# Secure=true, HttpOnly=true, SameSite=lax
```

---

## Verification Commands

### Check OAuth Provider Exists
```bash
adsys authentik oauth-get viralvisions-io-client
```

### Check Authentik Reachable
```bash
curl https://auth.afterdarksys.com/application/o/viralvisions-io-client/.well-known/openid-configuration
```

### Check Service Redirect
```bash
curl -I https://viralvisions.io/login
# Should see: Location: https://auth.afterdarksys.com/...
```

---

## Timeline

| Day | Date | Tasks | Services |
|-----|------|-------|----------|
| Day 1 | Jan 28 | Infrastructure | 6 services |
| Day 2 | Jan 29 | API + AI | 8 services |
| Day 3 | Jan 30 | Business + Community | 10 services |
| Day 4 | Jan 31 | Security | 5 services |
| Day 5 | Feb 1 | Testing & Fixes | All 29 |
| **Day 6** | **Feb 2** | **🚀 LAUNCH** | **All 29** |

---

## Need Help?

- **Full deployment guide**: See `LAUNCH_CHECKLIST_FEB2.md`
- **Code templates**: See `OAUTH_MIDDLEWARE_TEMPLATE.md`
- **Architecture details**: See `DEPLOYMENT_SUMMARY.md`
- **Authentik logs**: `docker logs authentik-server-prod`
- **List providers**: `adsys authentik oauth-list`

---

## Status Dashboard

Track progress:

```bash
# Create a tracking file
cat > deployment_status.txt <<EOF
Infrastructure (6):
[ ] afterdarksys.com
[ ] telcocloud.io
[ ] darkstorage.io
[ ] console.darkapi.io
[ ] web3dns.io
[ ] onedns.io

AI Platforms (6):
[ ] aeims.app
[ ] promptery.io
[ ] aiserve.farm
[ ] model2go.com
[ ] petalarm.ai
[ ] basebot.ai

API Services (2):
[ ] computeapi.io
[ ] systemapi.io

Business (5):
[ ] viralvisions.io
[ ] shipshack.io
[ ] flipdomain.io
[ ] itz.agency
[ ] afterapps.io

Community (5):
[ ] purrr.love
[ ] purrr.me
[ ] cats.center
[ ] dogs.institute
[ ] lonely.fyi

Security (5):
[ ] veribits.com
[ ] llmsecurity.dev
[ ] flipid.io
[ ] betterphish.io
[ ] filehashes.io
EOF

# Update as you deploy
# Change [ ] to [x] when done
```

---

**Ready to deploy!** Start with infrastructure services and work your way through the list. 🚀
