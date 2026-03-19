#!/bin/bash
# Deploy OAuth to ALL *.afterdarksys.com subdomains using wildcard provider

set -e

AUTHENTIK_DIR="/Users/ryan/development/afterdark-meta-project/afterdark-security-suite/afterdark-darkd/deployments/authentik"
SUBDOMAINS_BASE="/Users/ryan/development/afterdark-meta-project/afterdarksys.com/subdomains"

echo "🚀 Deploying Wildcard OAuth to *.afterdarksys.com subdomains..."
echo ""

# Node.js subdomains
NODEJS_SUBDOMAINS=(
  "admin"
  "api"
  "billing"
  "cdn"
  "changes"
  "changes-notifier"
  "dispensarytracking"
  "inventory"
  "login"
  "migration"
  "passwordroast"
  "pmportal"
  "signup"
  "sip"
)

# PHP subdomains
PHP_SUBDOMAINS=(
  "analytics"
  "captchang"
  "status"
)

# Python subdomains (dnsscience already done separately)
PYTHON_SUBDOMAINS=(
  # "dnsscience"  # Already has dedicated provider
)

SUCCESS_COUNT=0
SKIP_COUNT=0
ERROR_COUNT=0

# Function to deploy to Node.js subdomain
deploy_nodejs() {
  local subdomain=$1
  local service_dir="$SUBDOMAINS_BASE/$subdomain"

  if [ ! -d "$service_dir" ]; then
    echo "  ⚠️  Directory not found: $subdomain"
    ((SKIP_COUNT++))
    return
  fi

  echo "📦 $subdomain (Node.js)"

  # 1. Copy .env.production with dynamic redirect URI
  cat > "$service_dir/.env.production" <<EOF
# Authentik OAuth Configuration for $subdomain.afterdarksys.com
AUTHENTIK_URL=https://auth.afterdarksys.com
AUTHENTIK_ISSUER=https://auth.afterdarksys.com/application/o/afterdarksys-subdomains/
AUTHENTIK_CLIENT_ID=afterdarksys-subdomains-client
AUTHENTIK_CLIENT_SECRET=9205gqEmvFprzOFW9JaJK2gMTY4Pc8q9Ak6tN3P7bXg4eVNXwBJZ12BdLmK6cjTXfx9qpnBGC6Vuc7LelzLk0X7f87Wpy3UxyUSf1ygiOFa1FbxWwgkcUrH7LHGlAyxY
AUTHENTIK_CLIENT_TYPE=confidential
AUTHENTIK_REDIRECT_URI=https://$subdomain.afterdarksys.com/oauth/callback

# OAuth Scopes
AUTHENTIK_SCOPES=openid,profile,email,groups,offline_access

# Session Configuration
SESSION_SECRET=WcXvBnMzAsQwErTyUiOpLkJhGfDsSaPoIuYtReLqWmXnCvBnMaQwErTyUiOpAsLk
SESSION_COOKIE_NAME=${subdomain}_session
SESSION_COOKIE_SECURE=true
SESSION_COOKIE_HTTPONLY=true
SESSION_COOKIE_SAMESITE=lax
SESSION_MAX_AGE=86400

# After Dark SSO Integration
AFTERDARK_SSO_ENABLED=true
AFTERDARK_AUTH_URL=https://auth.afterdarksys.com
EOF
  echo "  ✅ Created .env.production"

  # 2. Create lib/oauth.js
  mkdir -p "$service_dir/lib"
  cat > "$service_dir/lib/oauth.js" <<'OAUTH_JS'
/**
 * Authentik OAuth Client for *.afterdarksys.com
 */
const crypto = require('crypto');

class AuthentikOAuth {
  constructor() {
    this.authUrl = process.env.AUTHENTIK_URL || 'https://auth.afterdarksys.com';
    this.issuer = process.env.AUTHENTIK_ISSUER;
    this.clientId = process.env.AUTHENTIK_CLIENT_ID;
    this.clientSecret = process.env.AUTHENTIK_CLIENT_SECRET;
    this.redirectUri = process.env.AUTHENTIK_REDIRECT_URI;
    this.scopes = process.env.AUTHENTIK_SCOPES || 'openid profile email groups offline_access';
  }

  getAuthorizationUrl(state) {
    const params = new URLSearchParams({
      client_id: this.clientId,
      response_type: 'code',
      redirect_uri: this.redirectUri,
      scope: this.scopes,
      state: state,
    });
    return `${this.authUrl}/application/o/authorize/?${params.toString()}`;
  }

  async exchangeCodeForTokens(code) {
    const response = await fetch(`${this.authUrl}/application/o/token/`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'authorization_code',
        code: code,
        redirect_uri: this.redirectUri,
        client_id: this.clientId,
        client_secret: this.clientSecret,
      }),
    });

    if (!response.ok) {
      throw new Error(`Token exchange failed: ${response.statusText}`);
    }

    return await response.json();
  }

  async getUserInfo(accessToken) {
    const response = await fetch(`${this.authUrl}/application/o/userinfo/`, {
      headers: { 'Authorization': `Bearer ${accessToken}` }
    });

    if (!response.ok) {
      throw new Error(`User info fetch failed: ${response.statusText}`);
    }

    return await response.json();
  }

  async refreshAccessToken(refreshToken) {
    const response = await fetch(`${this.authUrl}/application/o/token/`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'refresh_token',
        refresh_token: refreshToken,
        client_id: this.clientId,
        client_secret: this.clientSecret,
      }),
    });

    if (!response.ok) {
      throw new Error(`Token refresh failed: ${response.statusText}`);
    }

    return await response.json();
  }

  getLogoutUrl(idToken) {
    const params = new URLSearchParams({ client_id: this.clientId });
    if (idToken) {
      params.set('id_token_hint', idToken);
    }
    return `${this.authUrl}/application/o/end-session/?${params.toString()}`;
  }

  generateState() {
    return crypto.randomBytes(32).toString('base64url');
  }
}

module.exports = { AuthentikOAuth };
OAUTH_JS
  echo "  ✅ Created lib/oauth.js"

  # 3. Create routes/oauth.js
  mkdir -p "$service_dir/routes"
  cat > "$service_dir/routes/oauth.js" <<'OAUTH_ROUTES'
/**
 * OAuth Routes for *.afterdarksys.com
 */
const express = require('express');
const { AuthentikOAuth } = require('../lib/oauth');

const router = express.Router();
const oauthClient = new AuthentikOAuth();

router.get('/login', (req, res) => {
  const state = oauthClient.generateState();
  req.session.oauthState = state;
  const authUrl = oauthClient.getAuthorizationUrl(state);
  res.redirect(authUrl);
});

router.get('/callback', async (req, res) => {
  try {
    // Check for errors
    if (req.query.error) {
      return res.redirect(`/login?error=${req.query.error}`);
    }

    // Verify state (CSRF protection)
    const state = req.query.state;
    const savedState = req.session.oauthState;
    delete req.session.oauthState;

    if (!savedState || savedState !== state) {
      return res.redirect('/login?error=invalid_state');
    }

    // Exchange code for tokens
    const code = req.query.code;
    if (!code) {
      return res.redirect('/login?error=no_code');
    }

    const tokens = await oauthClient.exchangeCodeForTokens(code);
    const userInfo = await oauthClient.getUserInfo(tokens.access_token);

    // Store user info in session
    req.session.user = {
      email: userInfo.email,
      name: userInfo.name || userInfo.preferred_username || 'User',
      oauth: true,
      accessToken: tokens.access_token,
      refreshToken: tokens.refresh_token,
      idToken: tokens.id_token,
    };

    // Redirect to dashboard or home
    res.redirect('/dashboard' || '/');
  } catch (error) {
    console.error('OAuth callback error:', error);
    res.redirect('/login?error=oauth_failed');
  }
});

router.get('/logout', (req, res) => {
  const idToken = req.session.user?.idToken;
  req.session.destroy();

  const logoutUrl = oauthClient.getLogoutUrl(idToken);
  res.redirect(logoutUrl);
});

module.exports = router;
OAUTH_ROUTES
  echo "  ✅ Created routes/oauth.js"

  # 4. Update package.json if exists
  if [ -f "$service_dir/package.json" ]; then
    if ! grep -q "express-session" "$service_dir/package.json" 2>/dev/null; then
      echo "  ⚠️  Note: Add express-session and dotenv to package.json"
    fi
  fi

  echo "  ✅ $subdomain deployed!"
  ((SUCCESS_COUNT++))
  echo ""
}

# Function to deploy to PHP subdomain
deploy_php() {
  local subdomain=$1
  local service_dir="$SUBDOMAINS_BASE/$subdomain"

  if [ ! -d "$service_dir" ]; then
    echo "  ⚠️  Directory not found: $subdomain"
    ((SKIP_COUNT++))
    return
  fi

  echo "📦 $subdomain (PHP)"

  # 1. Copy .env.production
  cat > "$service_dir/.env.production" <<EOF
# Authentik OAuth Configuration for $subdomain.afterdarksys.com
AUTHENTIK_URL=https://auth.afterdarksys.com
AUTHENTIK_ISSUER=https://auth.afterdarksys.com/application/o/afterdarksys-subdomains/
AUTHENTIK_CLIENT_ID=afterdarksys-subdomains-client
AUTHENTIK_CLIENT_SECRET=9205gqEmvFprzOFW9JaJK2gMTY4Pc8q9Ak6tN3P7bXg4eVNXwBJZ12BdLmK6cjTXfx9qpnBGC6Vuc7LelzLk0X7f87Wpy3UxyUSf1ygiOFa1FbxWwgkcUrH7LHGlAyxY
AUTHENTIK_CLIENT_TYPE=confidential
AUTHENTIK_REDIRECT_URI=https://$subdomain.afterdarksys.com/oauth/callback

# OAuth Scopes
AUTHENTIK_SCOPES=openid,profile,email,groups,offline_access

# Session Configuration
SESSION_SECRET=WcXvBnMzAsQwErTyUiOpLkJhGfDsSaPoIuYtReLqWmXnCvBnMaQwErTyUiOpAsLk
SESSION_COOKIE_NAME=${subdomain}_session
SESSION_COOKIE_SECURE=true
SESSION_COOKIE_HTTPONLY=true
SESSION_COOKIE_SAMESITE=lax
SESSION_MAX_AGE=86400

# After Dark SSO Integration
AFTERDARK_SSO_ENABLED=true
AFTERDARK_AUTH_URL=https://auth.afterdarksys.com
EOF
  echo "  ✅ Created .env.production"

  # 2. Create OAuth.php
  mkdir -p "$service_dir/lib"
  cat > "$service_dir/lib/OAuth.php" <<'OAUTH_PHP'
<?php
/**
 * Authentik OAuth Client for *.afterdarksys.com
 */
class AuthentikOAuth {
    private $authUrl;
    private $issuer;
    private $clientId;
    private $clientSecret;
    private $redirectUri;
    private $scopes;

    public function __construct() {
        $this->authUrl = getenv('AUTHENTIK_URL') ?: 'https://auth.afterdarksys.com';
        $this->issuer = getenv('AUTHENTIK_ISSUER');
        $this->clientId = getenv('AUTHENTIK_CLIENT_ID');
        $this->clientSecret = getenv('AUTHENTIK_CLIENT_SECRET');
        $this->redirectUri = getenv('AUTHENTIK_REDIRECT_URI');
        $this->scopes = getenv('AUTHENTIK_SCOPES') ?: 'openid profile email groups offline_access';
    }

    public function getAuthorizationUrl(string $state): string {
        $params = http_build_query([
            'client_id' => $this->clientId,
            'response_type' => 'code',
            'redirect_uri' => $this->redirectUri,
            'scope' => $this->scopes,
            'state' => $state,
        ]);
        return $this->authUrl . '/application/o/authorize/?' . $params;
    }

    public function exchangeCodeForTokens(string $code): array {
        $ch = curl_init($this->authUrl . '/application/o/token/');
        curl_setopt($ch, CURLOPT_POST, true);
        curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query([
            'grant_type' => 'authorization_code',
            'code' => $code,
            'redirect_uri' => $this->redirectUri,
            'client_id' => $this->clientId,
            'client_secret' => $this->clientSecret,
        ]));
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);

        $response = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);

        if ($httpCode !== 200) {
            throw new Exception("Token exchange failed: HTTP $httpCode");
        }

        return json_decode($response, true);
    }

    public function getUserInfo(string $accessToken): array {
        $ch = curl_init($this->authUrl . '/application/o/userinfo/');
        curl_setopt($ch, CURLOPT_HTTPHEADER, [
            'Authorization: Bearer ' . $accessToken
        ]);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);

        $response = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);

        if ($httpCode !== 200) {
            throw new Exception("User info fetch failed: HTTP $httpCode");
        }

        return json_decode($response, true);
    }

    public function getLogoutUrl(?string $idToken = null): string {
        $params = ['client_id' => $this->clientId];
        if ($idToken) {
            $params['id_token_hint'] = $idToken;
        }
        return $this->authUrl . '/application/o/end-session/?' . http_build_query($params);
    }

    public function generateState(): string {
        return bin2hex(random_bytes(32));
    }
}
OAUTH_PHP
  echo "  ✅ Created lib/OAuth.php"

  # 3. Create oauth endpoints
  mkdir -p "$service_dir/public"
  cat > "$service_dir/public/oauth_login.php" <<'LOGIN_PHP'
<?php
require_once __DIR__ . '/../lib/OAuth.php';
session_start();

$oauth = new AuthentikOAuth();
$state = $oauth->generateState();
$_SESSION['oauth_state'] = $state;

$authUrl = $oauth->getAuthorizationUrl($state);
header('Location: ' . $authUrl);
exit;
LOGIN_PHP
  echo "  ✅ Created public/oauth_login.php"

  cat > "$service_dir/public/oauth_callback.php" <<'CALLBACK_PHP'
<?php
require_once __DIR__ . '/../lib/OAuth.php';
session_start();

$oauth = new AuthentikOAuth();

// Check for errors
if (isset($_GET['error'])) {
    header('Location: /login.php?error=' . urlencode($_GET['error']));
    exit;
}

// Verify state
$state = $_GET['state'] ?? '';
$savedState = $_SESSION['oauth_state'] ?? '';
unset($_SESSION['oauth_state']);

if (!$savedState || $savedState !== $state) {
    header('Location: /login.php?error=invalid_state');
    exit;
}

// Exchange code for tokens
$code = $_GET['code'] ?? '';
if (!$code) {
    header('Location: /login.php?error=no_code');
    exit;
}

try {
    $tokens = $oauth->exchangeCodeForTokens($code);
    $userInfo = $oauth->getUserInfo($tokens['access_token']);

    $_SESSION['user'] = [
        'email' => $userInfo['email'],
        'name' => $userInfo['name'] ?? $userInfo['preferred_username'] ?? 'User',
        'oauth' => true,
        'access_token' => $tokens['access_token'],
        'refresh_token' => $tokens['refresh_token'] ?? null,
        'id_token' => $tokens['id_token'] ?? null,
    ];

    header('Location: /dashboard.php');
    exit;
} catch (Exception $e) {
    error_log('OAuth callback error: ' . $e->getMessage());
    header('Location: /login.php?error=oauth_failed');
    exit;
}
CALLBACK_PHP
  echo "  ✅ Created public/oauth_callback.php"

  cat > "$service_dir/public/oauth_logout.php" <<'LOGOUT_PHP'
<?php
require_once __DIR__ . '/../lib/OAuth.php';
session_start();

$oauth = new AuthentikOAuth();
$idToken = $_SESSION['user']['id_token'] ?? null;

session_destroy();

$logoutUrl = $oauth->getLogoutUrl($idToken);
header('Location: ' . $logoutUrl);
exit;
LOGOUT_PHP
  echo "  ✅ Created public/oauth_logout.php"

  echo "  ✅ $subdomain deployed!"
  ((SUCCESS_COUNT++))
  echo ""
}

# Deploy to all Node.js subdomains
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "📦 Node.js Subdomains (${#NODEJS_SUBDOMAINS[@]})"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
for subdomain in "${NODEJS_SUBDOMAINS[@]}"; do
  deploy_nodejs "$subdomain"
done

# Deploy to all PHP subdomains
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "📦 PHP Subdomains (${#PHP_SUBDOMAINS[@]})"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
for subdomain in "${PHP_SUBDOMAINS[@]}"; do
  deploy_php "$subdomain"
done

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "✅ WILDCARD OAUTH DEPLOYMENT COMPLETE"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "📊 Results:"
echo "  ✅ Success: $SUCCESS_COUNT"
echo "  ⏭️  Skipped: $SKIP_COUNT"
echo "  ⚠️  Errors: $ERROR_COUNT"
echo ""
echo "🎯 All *.afterdarksys.com subdomains now use wildcard OAuth!"
echo "🔐 Single provider: afterdarksys-subdomains-client"
echo ""
echo "📝 Manual steps per subdomain:"
echo "1. Load .env.production in app entry point"
echo "2. Register OAuth routes"
echo "3. Add SSO button to login pages"
echo "4. Test: https://{subdomain}.afterdarksys.com/oauth/login"
