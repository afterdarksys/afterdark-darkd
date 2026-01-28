# OAuth2 Endpoints for AfterDark Applications

## Authentik OAuth2 Endpoints

### AfterDark Security Suite

**Authorization URL:** `http://127.0.0.1:9000/application/o/authorize/`
**Token URL:** `http://127.0.0.1:9000/application/o/token/`
**User Info URL:** `http://127.0.0.1:9000/application/o/userinfo/`
**Callback URL:** `http://localhost:9090/oauth/callback`

**Client ID:** `afterdark-security-suite`
**Client Secret:** See `.env` file

### Configuration Example (Go)

```go
oauth2Config := &oauth2.Config{
    ClientID:     "afterdark-security-suite",
    ClientSecret: os.Getenv("AFTERDARK_SECURITY_SUITE_CLIENT_SECRET"),
    Endpoint: oauth2.Endpoint{
        AuthURL:  "http://127.0.0.1:9000/application/o/authorize/",
        TokenURL: "http://127.0.0.1:9000/application/o/token/",
    },
    RedirectURL: "http://localhost:9090/oauth/callback",
    Scopes:      []string{"openid", "profile", "email"},
}
```

### Configuration Example (Environment Variables)

```bash
# Authentik OAuth2 Configuration
OAUTH_PROVIDER=authentik
OAUTH_AUTHORIZE_URL=http://127.0.0.1:9000/application/o/authorize/
OAUTH_TOKEN_URL=http://127.0.0.1:9000/application/o/token/
OAUTH_USERINFO_URL=http://127.0.0.1:9000/application/o/userinfo/
OAUTH_REDIRECT_URI=http://localhost:9090/oauth/callback
OAUTH_CLIENT_ID=afterdark-security-suite
OAUTH_CLIENT_SECRET=<from .env file>
OAUTH_SCOPES=openid,profile,email
```

## AfterDark HTTP Proxy

**Authorization URL:** `http://127.0.0.1:9000/application/o/authorize/`
**Token URL:** `http://127.0.0.1:9000/application/o/token/`
**User Info URL:** `http://127.0.0.1:9000/application/o/userinfo/`
**Callback URL:** `http://localhost:8080/oauth/callback`

**Client ID:** `ads-httpproxy-client`
**Client Secret:** See `.env` file

## AfterDark Management Console

**Authorization URL:** `http://127.0.0.1:9000/application/o/authorize/`
**Token URL:** `http://127.0.0.1:9000/application/o/token/`
**User Info URL:** `http://127.0.0.1:9000/application/o/userinfo/`
**Callback URL:** `http://localhost:9100/oauth/callback`

**Client ID:** `ads-management-console`
**Client Secret:** See `.env` file

## Testing OAuth Flow

### 1. Authorization Code Flow

```bash
# Step 1: Get authorization code (open in browser)
http://127.0.0.1:9000/application/o/authorize/?client_id=afterdark-security-suite&redirect_uri=http://localhost:9090/oauth/callback&response_type=code&scope=openid%20profile%20email

# Step 2: Exchange code for token
curl -X POST http://127.0.0.1:9000/application/o/token/ \
  -d "grant_type=authorization_code" \
  -d "code=<authorization_code>" \
  -d "redirect_uri=http://localhost:9090/oauth/callback" \
  -d "client_id=afterdark-security-suite" \
  -d "client_secret=<client_secret>"

# Step 3: Get user info
curl -H "Authorization: Bearer <access_token>" \
  http://127.0.0.1:9000/application/o/userinfo/
```

## Notes

- All OAuth endpoints use `127.0.0.1:9000` (not `localhost:9000`)
- Callback URLs use `localhost` (not `127.0.0.1`)
- This is intentional for Authentik's redirect validation
- Default scopes: `openid`, `profile`, `email`
- Token endpoint supports both POST body and Basic Auth
- Access tokens are JWT format (can be verified with signing key)
