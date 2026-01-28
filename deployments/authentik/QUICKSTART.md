# Authentik Quick Start

The bootstrap completed most setup. Here are the final manual steps:

## Current Status

✅ Admin user created: `akadmin` / `AfterDark2026!`
✅ OAuth2 provider created: `afterdark-security-suite`
⚠️  API token needs manual creation

## Final Setup (2 minutes)

### 1. Login to Authentik

```bash
open http://localhost:9000
```

**Credentials:**
- Username: `akadmin`
- Password: `AfterDark2026!`

### 2. Create API Token

1. Go to **Directory** → **Tokens & App passwords**
2. Click **Create** → **Tokens**
3. Fill in:
   - **Identifier**: `automation-token`
   - **User**: akadmin
   - **Intent**: API
   - **Expiring**: Uncheck (never expires)
4. Click **Create** and copy the token

### 3. Save Token to .env

```bash
cd /Users/ryan/development/afterdark-meta-project/afterdark-security-suite/afterdark-darkd/deployments/authentik

cat > .env << EOF
AUTHENTIK_TOKEN=<paste-token-here>
AUTHENTIK_URL=http://localhost:9000
AUTHENTIK_ADMIN_USER=akadmin
EOF
```

### 4. Verify Setup

```bash
# Test authentication
make test-auth

# List applications
make list-apps

# Export configuration
make export

# Check status
make status
```

## OAuth2 Application

The bootstrap created:
- **Application**: AfterDark Security Suite
- **Slug**: `afterdark-security-suite`
- **Client ID**: `afterdark-security-suite`

To get credentials:
1. Go to **Applications** → **Providers**
2. Click on **AfterDark OAuth2 Provider**
3. Copy **Client ID** and **Client Secret**

## All Make Commands

```bash
make help                 # Show all commands
make bootstrap            # Re-run bootstrap (idempotent)
make status               # Show Authentik status
make export               # Export config to JSON
make list-apps            # List applications
make list-users           # List users
make list-providers       # List OAuth/SAML providers
make create-user          # Create new user (interactive)
make reset-password       # Reset user password
make logs                 # Tail logs
```

## Troubleshooting

### Can't Login

```bash
# Reset password
docker exec authentik-server-prod python -m manage shell << 'EOF'
from authentik.core.models import User
user = User.objects.get(username='akadmin')
user.set_password('AfterDark2026!')
user.save()
print(f'Password reset for {user.username}')
EOF
```

### API Token Not Working

Create a new token via UI (see step 2 above)

### Export Failing

```bash
# Check token
cat .env

# Test API
curl -H "Authorization: Bearer $(grep AUTHENTIK_TOKEN .env | cut -d= -f2)" \
  http://localhost:9000/api/v3/core/applications/
```

## Next Steps

1. Export baseline configuration: `make export`
2. Commit to git: `git add config/ && git commit -m "Add Authentik baseline"`
3. Customize blueprints in `blueprints/`
4. Integrate with your apps using OAuth2

## Production Notes

For production:
- Change admin password
- Use external PostgreSQL
- Enable HTTPS
- Set secure `SECRET_KEY`
- Configure email
- Enable backups
- Restrict API tokens

See [README.md](README.md) for full documentation.
