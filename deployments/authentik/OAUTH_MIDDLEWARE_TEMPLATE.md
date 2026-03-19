# OAuth Middleware Implementation Templates

## For Go Services

### 1. Install Dependencies

```bash
go get github.com/coreos/go-oidc/v3/oidc
go get golang.org/x/oauth2
go get github.com/gorilla/sessions
```

### 2. Create `oauth.go` in your service

```go
package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"os"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/gorilla/sessions"
	"golang.org/x/oauth2"
)

var (
	// OAuth configuration
	oauth2Config *oauth2.Config
	oidcVerifier *oidc.IDTokenVerifier
	sessionStore *sessions.CookieStore
)

// InitOAuth initializes OAuth configuration from environment variables
func InitOAuth() error {
	// Load from .env.production
	issuer := os.Getenv("AUTHENTIK_ISSUER")
	clientID := os.Getenv("AUTHENTIK_CLIENT_ID")
	clientSecret := os.Getenv("AUTHENTIK_CLIENT_SECRET")
	redirectURI := os.Getenv("AUTHENTIK_REDIRECT_URI")
	sessionSecret := os.Getenv("SESSION_SECRET")

	if issuer == "" || clientID == "" || clientSecret == "" || redirectURI == "" {
		return fmt.Errorf("missing OAuth environment variables")
	}

	// Set up OIDC provider
	ctx := context.Background()
	provider, err := oidc.NewProvider(ctx, issuer)
	if err != nil {
		return fmt.Errorf("failed to create OIDC provider: %w", err)
	}

	// Configure OAuth2
	oauth2Config = &oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURI,
		Endpoint:     provider.Endpoint(),
		Scopes:       []string{oidc.ScopeOpenID, "profile", "email", "groups"},
	}

	// Configure ID token verifier
	oidcVerifier = provider.Verifier(&oidc.Config{ClientID: clientID})

	// Configure session store
	sessionStore = sessions.NewCookieStore([]byte(sessionSecret))
	sessionStore.Options = &sessions.Options{
		Path:     "/",
		MaxAge:   86400,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	}

	return nil
}

// generateState generates a random state parameter for OAuth
func generateState() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b), nil
}

// HandleLogin redirects to Authentik for authentication
func HandleLogin(w http.ResponseWriter, r *http.Request) {
	state, err := generateState()
	if err != nil {
		http.Error(w, "Failed to generate state", http.StatusInternalServerError)
		return
	}

	// Store state in session
	session, _ := sessionStore.Get(r, os.Getenv("SESSION_COOKIE_NAME"))
	session.Values["state"] = state
	session.Save(r, w)

	// Redirect to Authentik
	url := oauth2Config.AuthCodeURL(state)
	http.Redirect(w, r, url, http.StatusFound)
}

// HandleCallback handles the OAuth callback from Authentik
func HandleCallback(w http.ResponseWriter, r *http.Request) {
	// Get session
	session, _ := sessionStore.Get(r, os.Getenv("SESSION_COOKIE_NAME"))

	// Verify state
	if r.URL.Query().Get("state") != session.Values["state"] {
		http.Error(w, "Invalid state parameter", http.StatusBadRequest)
		return
	}

	// Exchange code for token
	ctx := context.Background()
	oauth2Token, err := oauth2Config.Exchange(ctx, r.URL.Query().Get("code"))
	if err != nil {
		http.Error(w, "Failed to exchange token: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Extract the ID Token from OAuth2 token
	rawIDToken, ok := oauth2Token.Extra("id_token").(string)
	if !ok {
		http.Error(w, "No id_token field in oauth2 token", http.StatusInternalServerError)
		return
	}

	// Verify ID Token
	idToken, err := oidcVerifier.Verify(ctx, rawIDToken)
	if err != nil {
		http.Error(w, "Failed to verify ID Token: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Extract claims
	var claims struct {
		Email         string   `json:"email"`
		Name          string   `json:"name"`
		PreferredUsername string `json:"preferred_username"`
		Groups        []string `json:"groups"`
	}
	if err := idToken.Claims(&claims); err != nil {
		http.Error(w, "Failed to parse claims: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Store user info in session
	session.Values["authenticated"] = true
	session.Values["email"] = claims.Email
	session.Values["name"] = claims.Name
	session.Values["username"] = claims.PreferredUsername
	session.Values["groups"] = claims.Groups
	session.Values["access_token"] = oauth2Token.AccessToken
	session.Save(r, w)

	// Redirect to home
	http.Redirect(w, r, "/", http.StatusFound)
}

// HandleLogout logs out the user
func HandleLogout(w http.ResponseWriter, r *http.Request) {
	session, _ := sessionStore.Get(r, os.Getenv("SESSION_COOKIE_NAME"))
	session.Options.MaxAge = -1
	session.Save(r, w)
	http.Redirect(w, r, "/", http.StatusFound)
}

// RequireAuth is middleware that requires authentication
func RequireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		session, _ := sessionStore.Get(r, os.Getenv("SESSION_COOKIE_NAME"))
		authenticated, ok := session.Values["authenticated"].(bool)
		if !ok || !authenticated {
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}
		next(w, r)
	}
}

// GetCurrentUser returns the current user from session
func GetCurrentUser(r *http.Request) map[string]interface{} {
	session, _ := sessionStore.Get(r, os.Getenv("SESSION_COOKIE_NAME"))
	if authenticated, ok := session.Values["authenticated"].(bool); !ok || !authenticated {
		return nil
	}
	return map[string]interface{}{
		"email":    session.Values["email"],
		"name":     session.Values["name"],
		"username": session.Values["username"],
		"groups":   session.Values["groups"],
	}
}

// HandleUserInfo returns current user info as JSON
func HandleUserInfo(w http.ResponseWriter, r *http.Request) {
	user := GetCurrentUser(r)
	if user == nil {
		http.Error(w, "Not authenticated", http.StatusUnauthorized)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(user)
}
```

### 3. Update `main.go`

```go
package main

import (
	"log"
	"net/http"
	"os"

	"github.com/joho/godotenv"
)

func main() {
	// Load .env.production
	if err := godotenv.Load(".env.production"); err != nil {
		log.Printf("Warning: .env.production not found: %v", err)
	}

	// Initialize OAuth
	if err := InitOAuth(); err != nil {
		log.Fatalf("Failed to initialize OAuth: %v", err)
	}

	// OAuth routes
	http.HandleFunc("/login", HandleLogin)
	http.HandleFunc("/oauth/callback", HandleCallback)
	http.HandleFunc("/logout", HandleLogout)
	http.HandleFunc("/api/user", HandleUserInfo)

	// Protected routes
	http.HandleFunc("/dashboard", RequireAuth(func(w http.ResponseWriter, r *http.Request) {
		user := GetCurrentUser(r)
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte("<h1>Dashboard</h1><p>Welcome, " + user["name"].(string) + "!</p>"))
	}))

	// Public routes
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		user := GetCurrentUser(r)
		if user != nil {
			w.Write([]byte("<h1>Welcome, " + user["name"].(string) + "</h1><a href='/logout'>Logout</a>"))
		} else {
			w.Write([]byte("<h1>Welcome</h1><a href='/login'>Login</a>"))
		}
	})

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	log.Printf("Server starting on :%s", port)
	if err := http.ListenAndServe(":"+port, nil); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}
```

### 4. Add to `go.mod`

```bash
go mod tidy
```

---

## For Node.js Services

### 1. Install Dependencies

```bash
npm install openid-client express-session dotenv
```

### 2. Create `oauth.js`

```javascript
const { Issuer } = require('openid-client');
const session = require('express-session');

let client;
let sessionMiddleware;

async function initOAuth() {
  const issuer = await Issuer.discover(process.env.AUTHENTIK_ISSUER);

  client = new issuer.Client({
    client_id: process.env.AUTHENTIK_CLIENT_ID,
    client_secret: process.env.AUTHENTIK_CLIENT_SECRET,
    redirect_uris: [process.env.AUTHENTIK_REDIRECT_URI],
    response_types: ['code'],
  });

  sessionMiddleware = session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
      secure: true,
      httpOnly: true,
      maxAge: 86400000,
    },
  });

  return { client, sessionMiddleware };
}

function requireAuth(req, res, next) {
  if (!req.session.user) {
    return res.redirect('/login');
  }
  next();
}

module.exports = { initOAuth, requireAuth };
```

### 3. Update `server.js`

```javascript
require('dotenv').config({ path: '.env.production' });
const express = require('express');
const { initOAuth, requireAuth } = require('./oauth');
const { generators } = require('openid-client');

const app = express();

let client, sessionMiddleware;

(async () => {
  const oauth = await initOAuth();
  client = oauth.client;
  sessionMiddleware = oauth.sessionMiddleware;

  app.use(sessionMiddleware);

  // OAuth routes
  app.get('/login', (req, res) => {
    const state = generators.state();
    const nonce = generators.nonce();
    req.session.state = state;
    req.session.nonce = nonce;

    const authUrl = client.authorizationUrl({
      scope: 'openid profile email groups',
      state,
      nonce,
    });

    res.redirect(authUrl);
  });

  app.get('/oauth/callback', async (req, res) => {
    const params = client.callbackParams(req);
    const tokenSet = await client.callback(
      process.env.AUTHENTIK_REDIRECT_URI,
      params,
      { state: req.session.state, nonce: req.session.nonce }
    );

    const userinfo = await client.userinfo(tokenSet);
    req.session.user = userinfo;
    res.redirect('/');
  });

  app.get('/logout', (req, res) => {
    req.session.destroy();
    res.redirect('/');
  });

  // Protected route
  app.get('/dashboard', requireAuth, (req, res) => {
    res.send(`<h1>Dashboard</h1><p>Welcome, ${req.session.user.name}!</p>`);
  });

  // Public route
  app.get('/', (req, res) => {
    if (req.session.user) {
      res.send(`<h1>Welcome, ${req.session.user.name}</h1><a href='/logout'>Logout</a>`);
    } else {
      res.send('<h1>Welcome</h1><a href='/login'>Login</a>');
    }
  });

  const PORT = process.env.PORT || 3000;
  app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
  });
})();
```

---

## For Python Services

### 1. Install Dependencies

```bash
pip install authlib requests python-dotenv flask
```

### 2. Create `oauth.py`

```python
from authlib.integrations.flask_client import OAuth
from flask import Flask, session, redirect, url_for, request
from functools import wraps
import os
from dotenv import load_dotenv

load_dotenv('.env.production')

app = Flask(__name__)
app.secret_key = os.getenv('SESSION_SECRET')

oauth = OAuth(app)
authentik = oauth.register(
    'authentik',
    client_id=os.getenv('AUTHENTIK_CLIENT_ID'),
    client_secret=os.getenv('AUTHENTIK_CLIENT_SECRET'),
    server_metadata_url=os.getenv('AUTHENTIK_ISSUER') + '.well-known/openid-configuration',
    client_kwargs={
        'scope': 'openid profile email groups'
    }
)

def require_auth(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/login')
def login():
    redirect_uri = os.getenv('AUTHENTIK_REDIRECT_URI')
    return authentik.authorize_redirect(redirect_uri)

@app.route('/oauth/callback')
def callback():
    token = authentik.authorize_access_token()
    user = authentik.parse_id_token(token)
    session['user'] = user
    return redirect('/')

@app.route('/logout')
def logout():
    session.pop('user', None)
    return redirect('/')

@app.route('/')
def index():
    user = session.get('user')
    if user:
        return f"<h1>Welcome, {user['name']}</h1><a href='/logout'>Logout</a>"
    return "<h1>Welcome</h1><a href='/login'>Login</a>"

@app.route('/dashboard')
@require_auth
def dashboard():
    user = session['user']
    return f"<h1>Dashboard</h1><p>Welcome, {user['name']}!</p>"

if __name__ == '__main__':
    app.run(port=int(os.getenv('PORT', 5000)))
```

---

## Deployment Checklist for Each Service

1. **Copy .env.production** to service directory
2. **Install dependencies** (Go: `go mod tidy`, Node: `npm install`, Python: `pip install`)
3. **Add OAuth code** (copy templates above)
4. **Update routes** to use `RequireAuth` middleware on protected endpoints
5. **Test locally** with `DEV_MODE=true` and localhost redirect
6. **Build & deploy** to production
7. **Test OAuth flow** (login, logout, protected routes)
8. **Monitor logs** for OAuth errors

---

## Testing OAuth Flow

### Manual Test Steps

For each service:

1. **Visit service URL**: `https://[domain]/`
2. **Click Login**: Should redirect to `auth.afterdarksys.com`
3. **Enter credentials**: Use your Authentik account
4. **Redirected back**: Should see logged-in state
5. **Access protected route**: E.g., `/dashboard`
6. **Click Logout**: Should log out and redirect
7. **Try protected route**: Should redirect to login

### Automated Test Script

```bash
#!/bin/bash
# test_oauth.sh [domain]

DOMAIN=$1

echo "Testing OAuth on $DOMAIN..."

# Test 1: Home page accessible
echo -n "  1. Home page: "
if curl -s -o /dev/null -w "%{http_code}" "https://$DOMAIN" | grep -q "200"; then
  echo "✓"
else
  echo "✗"
fi

# Test 2: Login redirects to Authentik
echo -n "  2. Login redirect: "
if curl -sI "https://$DOMAIN/login" | grep -q "auth.afterdarksys.com"; then
  echo "✓"
else
  echo "✗"
fi

# Test 3: Protected route redirects to login
echo -n "  3. Protected route: "
if curl -sI "https://$DOMAIN/dashboard" | grep -q "/login"; then
  echo "✓"
else
  echo "✗"
fi

echo "Done!"
```

---

## Troubleshooting

### Common Issues

1. **403 Forbidden**: Check client_id and client_secret
2. **Invalid redirect_uri**: Ensure redirect URI matches Authentik config
3. **State mismatch**: Check session configuration
4. **SSL errors**: Ensure SSL certificates are valid
5. **CORS errors**: Add `Access-Control-Allow-Origin` headers if needed

### Debug Checklist

- [ ] Environment variables loaded correctly
- [ ] Authentik provider exists in Authentik
- [ ] Redirect URI matches exactly
- [ ] SSL certificate valid
- [ ] Session secret set
- [ ] OAuth scopes correct
- [ ] Network connectivity to auth.afterdarksys.com

### Logs to Check

- Service application logs
- Authentik server logs: `docker logs authentik-server-prod`
- Nginx/proxy logs
- Browser console for client-side errors
