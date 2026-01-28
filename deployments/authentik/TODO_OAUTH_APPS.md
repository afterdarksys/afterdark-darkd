# OAuth Apps Still Need Creation

## Status

✅ **Created:**
- AfterDark Security Suite (client_id: `afterdark-security-suite`)
  - Client Secret saved in `.env`

❌ **Still Need:**
2 more apps need to be created via Authentik UI

## How to Create via UI

### 1. AfterDark HTTP Proxy

**Provider:**
- Go to Applications → Providers → Create
- Type: OAuth2/OpenID Provider
- Name: `AfterDark HTTP Proxy Provider`
- Client ID: `ads-httpproxy-client`
- Client Type: Confidential
- Redirect URIs:
  ```
  http://localhost:8080/oauth/callback
  https://proxy.afterdark.local/oauth/callback
  ```
- Signing Key: authentik Self-signed Certificate
- Create and **SAVE THE CLIENT SECRET**

**Application:**
- Go to Applications → Applications → Create
- Name: `AfterDark HTTP Proxy`
- Slug: `ads-httpproxy`
- Provider: Select the provider above
- Launch URL: `http://localhost:8080/`

### 2. AfterDark Management Console

**Provider:**
- Same steps as above
- Name: `AfterDark Management Console Provider`
- Client ID: `ads-management-console`
- Redirect URIs:
  ```
  http://localhost:9100/oauth/callback
  https://console.afterdark.local/oauth/callback
  ```

**Application:**
- Name: `AfterDark Management Console`
- Slug: `ads-management`
- Launch URL: `http://localhost:9100/`

## After Creation

Run this to save the secrets:

```bash
# Add to .env file
echo "ADS_HTTPPROXY_CLIENT_CLIENT_SECRET=<secret-here>" >> .env
echo "ADS_MANAGEMENT_CONSOLE_CLIENT_SECRET=<secret-here>" >> .env
```

## Why Manual?

- Authentik API tokens require specific permissions that are hard to configure programmatically
- Terraform provider has permission issues
- Python Django shell access works but hits dataclass serialization bugs
- UI is most reliable for now

## Future: Better Tooling Needed

Consider:
- Custom Authentik admin CLI tool
- Blueprints (YAML-based configuration)
- Direct PostgreSQL manipulation (hacky but works)
- Wait for better Terraform provider support
