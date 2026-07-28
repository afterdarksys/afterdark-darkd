# AfterDark User Accounts & OAuth Applications

**Authentik URL:** http://localhost:9000

## Admin Account

**Username:** `akadmin`
**Password:** `AfterDark2026!`
**Purpose:** Full administrative access

## User Accounts

All users have default password: `TempPass123!` (should be changed on first login)

| Username | Email | Full Name | Purpose |
|----------|-------|-----------|---------|
| john.doe | john@afterdark.local | John Doe | Example user |
| jane.smith | jane@afterdark.local | Jane Smith | Example user |
| dev.user | dev@afterdark.local | Development User | Development/testing |
| test.user | test@afterdark.local | Test User | QA/testing |

## OAuth2 Applications

### 1. AfterDark Security Suite
- **Slug:** `afterdark-security-suite`
- **Client ID:** `afterdark-security-suite`
- **Client Secret:** `h9WzY5KgE4TVFNmrBXIEDfhrUxqvhD54UP22LlMKfmoC0Lq8Y2A20JnPfx4lyDPUN9hwRVaqTHFYdXTVIiLYN5AnUNrPJrlBnLXNJU9mFs9LzpqhsiYqjdmOqgSkwwQn`
- **Redirect URIs:**
  - http://localhost:9090/oauth/callback
  - https://security.afterdark.local/oauth/callback
- **Launch URL:** http://localhost:9090/

### 2. AfterDark HTTP Proxy
- **Slug:** `ads-httpproxy`
- **Client ID:** `ads-httpproxy-client`
- **Redirect URIs:**
  - http://localhost:8080/oauth/callback
  - https://proxy.afterdark.local/oauth/callback
- **Launch URL:** http://localhost:9090/

### 3. AfterDark Management Console
- **Slug:** `ads-management`
- **Client ID:** `ads-management-console`
- **Redirect URIs:**
  - http://localhost:9100/oauth/callback
  - https://console.afterdark.local/oauth/callback
- **Launch URL:** http://localhost:9100/

## Getting Client Secrets

1. Login to Authentik: http://localhost:9000
2. Go to **Applications** → **Providers**
3. Click on the provider name (e.g., "AfterDark Security Suite OAuth2 Provider")
4. Copy the **Client Secret**

## Adding More Users

```bash
# Interactive mode
make create-user

# Or edit scripts/create_users.sh and run:
make create-users
```

## Adding More OAuth Apps

```bash
# Interactive mode
make setup-oauth-interactive

# Or edit scripts/setup_oauth_apps.sh and add your app
```

## User Login Flow

1. User goes to your app (e.g., http://localhost:9090)
2. App redirects to Authentik for login
3. User enters username/password
4. Authentik redirects back to app with OAuth code
5. App exchanges code for access token
6. User is logged in!

## Password Reset

```bash
# Reset any user password
make reset-password

# Or directly:
docker exec authentik-server-prod python -m manage shell << 'EOF'
from authentik.core.models import User
user = User.objects.get(username='john.doe')
user.set_password('NewPassword123!')
user.save()
EOF
```

## Notes

- All passwords should be changed on first login
- OAuth client secrets should be stored securely (env vars, secrets manager)
- For production, use external database and enable HTTPS
- Consider enabling 2FA/MFA for admin accounts
- Backup Authentik database regularly

## Quick Commands

```bash
# List all users
make list-users

# List all apps
make list-apps

# Check status
make status

# View logs
make logs
```
