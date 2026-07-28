# Launch Checklist - February 2, 2026

## 🎯 Mission: Deploy OAuth/SSO to All 29 Production Domains

**Launch Date**: February 2, 2026
**Current Status**: OAuth providers created ✅
**Remaining**: Deploy OAuth middleware to services + DNS/SSL

---

## ✅ Phase 1: OAuth Infrastructure (COMPLETED)

- [x] Create 21 localhost OAuth providers
- [x] Build custom OAuth CLI tool
- [x] Integrate into adsyslib
- [x] Create 29 production OAuth providers
- [x] Generate production credentials
- [x] Save secrets to config/.env.production

**Result**: 50 total OAuth providers ready in Authentik

---

## ⏳ Phase 2: Service Deployment (IN PROGRESS)

### For Each of 29 Services

#### Step 1: Deploy OAuth Client Library

**Go Services** (most services):
```bash
cd /path/to/service
go get github.com/coreos/go-oidc/v3/oidc
go get golang.org/x/oauth2
go get github.com/gorilla/sessions
```

**Node.js Services**:
```bash
npm install openid-client express-session
```

**Python Services**:
```bash
pip install authlib requests
```

#### Step 2: Add OAuth Configuration to Each Service

Extract credentials from `config/production_oauth_secrets.json` and create `.env.production` for each service:

```bash
# Example for viralvisions.io
AUTHENTIK_ISSUER=https://auth.afterdarksys.com/application/o/viralvisions-io-client/
AUTHENTIK_CLIENT_ID=viralvisions-io-client
AUTHENTIK_CLIENT_SECRET=<from production_oauth_secrets.json>
AUTHENTIK_REDIRECT_URI=https://viralvisions.io/oauth/callback
SESSION_SECRET=<generate-random-32-chars>
```

#### Step 3: Implement OAuth Middleware

Add to each service's main.go (or equivalent):

```go
// See OAUTH_MIDDLEWARE_TEMPLATE.md for full implementation
```

#### Step 4: Deploy Updated Service

```bash
# Build
docker build -t viralvisions:oauth .

# Deploy
docker-compose up -d viralvisions

# or
kubectl apply -f viralvisions-deployment.yaml
```

---

## 🔐 Phase 3: DNS & SSL (PARALLEL WITH PHASE 2)

### DNS Records

For each domain, ensure A/CNAME record points to your infrastructure:

**Quick Check Script**:
```bash
for domain in viralvisions.io aeims.app veribits.com telcocloud.io computeapi.io systemapi.io purrr.love purrr.me cats.center dogs.institute darkstorage.io shipshack.io console.darkapi.io promptery.io aiserve.farm lonely.fyi llmsecurity.dev model2go.com flipdomain.io flipid.io petalarm.ai web3dns.io itz.agency onedns.io betterphish.io basebot.ai filehashes.io afterapps.io; do
  echo "$domain: $(dig +short $domain | head -1)"
done
```

### SSL Certificates

**Option 1: Wildcard via Cloudflare** (FASTEST):
```bash
# Use Cloudflare's Universal SSL
# Set SSL mode to "Full (strict)"
# Auto-managed, zero config
```

**Option 2: Let's Encrypt** (RECOMMENDED):
```bash
# Install certbot
apt-get install certbot

# Get certs for each domain
for domain in viralvisions.io aeims.app ...; do
  certbot certonly --webroot -w /var/www/html \
    -d $domain -d www.$domain
done
```

**Option 3: Wildcard Let's Encrypt** (for *.afterdarksys.com):
```bash
certbot certonly --dns-cloudflare \
  --dns-cloudflare-credentials ~/.secrets/cloudflare.ini \
  -d "*.afterdarksys.com" -d "afterdarksys.com"
```

---

## 📋 Service-by-Service Checklist

### AI Platforms (6 services)

- [ ] **aeims.app** - AI Enterprise Management
  - [ ] OAuth middleware deployed
  - [ ] .env.production configured
  - [ ] DNS pointing to server
  - [ ] SSL certificate active
  - [ ] Login tested
  - [ ] Logout tested

- [ ] **promptery.io** - Prompt Engineering
  - [ ] OAuth middleware deployed
  - [ ] .env.production configured
  - [ ] DNS pointing to server
  - [ ] SSL certificate active
  - [ ] Login tested
  - [ ] Logout tested

- [ ] **aiserve.farm** - AI Service Orchestration
  - [ ] OAuth middleware deployed
  - [ ] .env.production configured
  - [ ] DNS pointing to server
  - [ ] SSL certificate active
  - [ ] Login tested
  - [ ] Logout tested

- [ ] **model2go.com** - Model Deployment
  - [ ] OAuth middleware deployed
  - [ ] .env.production configured
  - [ ] DNS pointing to server
  - [ ] SSL certificate active
  - [ ] Login tested
  - [ ] Logout tested

- [ ] **petalarm.ai** - Pet Monitoring
  - [ ] OAuth middleware deployed
  - [ ] .env.production configured
  - [ ] DNS pointing to server
  - [ ] SSL certificate active
  - [ ] Login tested
  - [ ] Logout tested

- [ ] **basebot.ai** - AI Chatbot Framework
  - [ ] OAuth middleware deployed
  - [ ] .env.production configured
  - [ ] DNS pointing to server
  - [ ] SSL certificate active
  - [ ] Login tested
  - [ ] Logout tested

### API Services (2 services)

- [ ] **computeapi.io** - Compute API
  - [ ] OAuth middleware deployed
  - [ ] .env.production configured
  - [ ] DNS pointing to server
  - [ ] SSL certificate active
  - [ ] API auth tested

- [ ] **systemapi.io** - System API Gateway
  - [ ] OAuth middleware deployed
  - [ ] .env.production configured
  - [ ] DNS pointing to server
  - [ ] SSL certificate active
  - [ ] API auth tested

### Business/Marketing (5 services)

- [ ] **viralvisions.io** - Marketing Analytics
  - [ ] OAuth middleware deployed
  - [ ] .env.production configured
  - [ ] DNS pointing to server
  - [ ] SSL certificate active
  - [ ] Login tested
  - [ ] Logout tested

- [ ] **shipshack.io** - Shipping/Logistics
  - [ ] OAuth middleware deployed
  - [ ] .env.production configured
  - [ ] DNS pointing to server
  - [ ] SSL certificate active
  - [ ] Login tested
  - [ ] Logout tested

- [ ] **flipdomain.io** - Domain Marketplace
  - [ ] OAuth middleware deployed
  - [ ] .env.production configured
  - [ ] DNS pointing to server
  - [ ] SSL certificate active
  - [ ] Login tested
  - [ ] Logout tested

- [ ] **itz.agency** - IT Consulting
  - [ ] OAuth middleware deployed
  - [ ] .env.production configured
  - [ ] DNS pointing to server
  - [ ] SSL certificate active
  - [ ] Login tested
  - [ ] Logout tested

- [ ] **afterapps.io** - App Marketplace
  - [ ] OAuth middleware deployed
  - [ ] .env.production configured
  - [ ] DNS pointing to server
  - [ ] SSL certificate active
  - [ ] Login tested
  - [ ] Logout tested

### Community/Social (5 services)

- [ ] **purrr.love** - Cat Community
  - [ ] OAuth middleware deployed
  - [ ] .env.production configured
  - [ ] DNS pointing to server
  - [ ] SSL certificate active
  - [ ] Login tested
  - [ ] Logout tested

- [ ] **purrr.me** - Personal Cat Profiles
  - [ ] OAuth middleware deployed
  - [ ] .env.production configured
  - [ ] DNS pointing to server
  - [ ] SSL certificate active
  - [ ] Login tested
  - [ ] Logout tested

- [ ] **cats.center** - Cat Enthusiast Hub
  - [ ] OAuth middleware deployed
  - [ ] .env.production configured
  - [ ] DNS pointing to server
  - [ ] SSL certificate active
  - [ ] Login tested
  - [ ] Logout tested

- [ ] **dogs.institute** - Dog Training
  - [ ] OAuth middleware deployed
  - [ ] .env.production configured
  - [ ] DNS pointing to server
  - [ ] SSL certificate active
  - [ ] Login tested
  - [ ] Logout tested

- [ ] **lonely.fyi** - Social Connection
  - [ ] OAuth middleware deployed
  - [ ] .env.production configured
  - [ ] DNS pointing to server
  - [ ] SSL certificate active
  - [ ] Login tested
  - [ ] Logout tested

### Infrastructure (6 services)

- [ ] **afterdarksys.com** - Main Company Site
  - [ ] OAuth middleware deployed
  - [ ] .env.production configured
  - [ ] DNS pointing to server
  - [ ] SSL certificate active (wildcard)
  - [ ] Login tested
  - [ ] Logout tested

- [ ] **telcocloud.io** - Telecom Cloud
  - [ ] OAuth middleware deployed
  - [ ] .env.production configured
  - [ ] DNS pointing to server
  - [ ] SSL certificate active
  - [ ] Login tested
  - [ ] Logout tested

- [ ] **darkstorage.io** - Storage Platform
  - [ ] OAuth middleware deployed
  - [ ] .env.production configured
  - [ ] DNS pointing to server
  - [ ] SSL certificate active
  - [ ] Login tested
  - [ ] Logout tested

- [ ] **console.darkapi.io** - DarkAPI Console
  - [ ] OAuth middleware deployed
  - [ ] .env.production configured
  - [ ] DNS pointing to server
  - [ ] SSL certificate active
  - [ ] Login tested
  - [ ] Logout tested

- [ ] **web3dns.io** - Web3 DNS
  - [ ] OAuth middleware deployed
  - [ ] .env.production configured
  - [ ] DNS pointing to server
  - [ ] SSL certificate active
  - [ ] Login tested
  - [ ] Logout tested

- [ ] **onedns.io** - DNS Management
  - [ ] OAuth middleware deployed
  - [ ] .env.production configured
  - [ ] DNS pointing to server
  - [ ] SSL certificate active
  - [ ] Login tested
  - [ ] Logout tested

### Security Tools (5 services)

- [ ] **veribits.com** - Verification Platform
  - [ ] OAuth middleware deployed
  - [ ] .env.production configured
  - [ ] DNS pointing to server
  - [ ] SSL certificate active
  - [ ] Login tested
  - [ ] Logout tested

- [ ] **llmsecurity.dev** - LLM Security Testing
  - [ ] OAuth middleware deployed
  - [ ] .env.production configured
  - [ ] DNS pointing to server
  - [ ] SSL certificate active
  - [ ] Login tested
  - [ ] Logout tested

- [ ] **flipid.io** - Identity Verification
  - [ ] OAuth middleware deployed
  - [ ] .env.production configured
  - [ ] DNS pointing to server
  - [ ] SSL certificate active
  - [ ] Login tested
  - [ ] Logout tested

- [ ] **betterphish.io** - Phishing Detection
  - [ ] OAuth middleware deployed
  - [ ] .env.production configured
  - [ ] DNS pointing to server
  - [ ] SSL certificate active
  - [ ] Login tested
  - [ ] Logout tested

- [ ] **filehashes.io** - File Hash Verification
  - [ ] OAuth middleware deployed
  - [ ] .env.production configured
  - [ ] DNS pointing to server
  - [ ] SSL certificate active
  - [ ] Login tested
  - [ ] Logout tested

---

## 🧪 Phase 4: Testing

### Automated Testing Script

```bash
#!/bin/bash
# test_all_oauth.sh

domains=(
  viralvisions.io aeims.app veribits.com
  telcocloud.io computeapi.io systemapi.io
  purrr.love purrr.me cats.center dogs.institute
  darkstorage.io shipshack.io console.darkapi.io
  promptery.io aiserve.farm lonely.fyi
  llmsecurity.dev model2go.com flipdomain.io flipid.io
  petalarm.ai web3dns.io itz.agency onedns.io
  betterphish.io basebot.ai filehashes.io afterapps.io
  afterdarksys.com
)

for domain in "${domains[@]}"; do
  echo "Testing $domain..."

  # Test HTTPS
  if curl -s -o /dev/null -w "%{http_code}" "https://$domain" | grep -q "200\|302"; then
    echo "  ✓ HTTPS working"
  else
    echo "  ✗ HTTPS failed"
  fi

  # Test OAuth redirect
  if curl -s "https://$domain/login" | grep -q "auth.afterdarksys.com"; then
    echo "  ✓ OAuth redirect configured"
  else
    echo "  ✗ OAuth redirect missing"
  fi
done
```

### Manual Testing Checklist

For each domain:
1. Open in browser: `https://[domain]`
2. Click "Login" button
3. Redirected to Authentik (auth.afterdarksys.com)
4. Enter credentials
5. Redirected back to service
6. Logged in successfully
7. Can access protected pages
8. Logout button works
9. Redirected to login after logout

---

## 📊 Progress Tracking

**Current Status as of Now**:
- ✅ OAuth providers created: 50/50 (100%)
- ⏳ Services with OAuth middleware: 0/29 (0%)
- ⏳ DNS configured: ?/29 (check with dig)
- ⏳ SSL certificates: ?/29 (check with openssl)
- ⏳ Services tested: 0/29 (0%)

**Target for Feb 2, 2026**:
- ✅ OAuth providers: 50/50 (100%)
- ✅ Services with OAuth: 29/29 (100%)
- ✅ DNS configured: 29/29 (100%)
- ✅ SSL certificates: 29/29 (100%)
- ✅ Services tested: 29/29 (100%)

---

## 🚀 Deployment Scripts

### Mass .env Generator

```bash
# Generate .env.production for all services
python3 scripts/generate_service_envs.py
```

### Mass Deployment

```bash
# Deploy all services with OAuth
./scripts/deploy_all_with_oauth.sh
```

---

## 📝 Notes

- **Launch Date**: February 2, 2026 (plenty of time!)
- **No Customers Yet**: Can deploy/test/break without worry
- **Priority Order**: Infrastructure → AI → Business → Security → Community
- **Rollback Plan**: Keep non-OAuth versions running until OAuth tested
- **Monitoring**: Set up alerts for OAuth failures before launch

---

## ✅ Definition of Done

For launch on Feb 2, 2026, we need:

1. **All 29 domains** have OAuth middleware deployed
2. **All 29 domains** have valid SSL certificates
3. **All 29 domains** have correct DNS records
4. **All 29 domains** redirect to Authentik for login
5. **All 29 domains** successfully log in and out
6. **All 29 domains** maintain session correctly
7. **Monitoring** in place for OAuth flows
8. **Documentation** complete for each service
9. **Backup plan** tested in case OAuth fails
10. **Team trained** on OAuth troubleshooting

---

## 🆘 Emergency Contacts

- **Authentik Issues**: Check docker logs: `docker logs authentik-server-prod`
- **OAuth Provider Issues**: Use adsyslib: `adsys authentik oauth-list`
- **Certificate Issues**: Check Let's Encrypt: `certbot certificates`
- **DNS Issues**: Check Cloudflare dashboard or DNS provider

---

**Next Immediate Action**: Generate per-service .env files and start deploying OAuth middleware to services, starting with infrastructure (afterdarksys.com, console.darkapi.io, etc.)
