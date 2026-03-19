#!/bin/bash
set -e

AUTHENTIK_DIR="/Users/ryan/development/afterdark-meta-project/afterdark-security-suite/afterdark-darkd/deployments/authentik"

echo "🚀 Deploying to missing services..."

# darkstorage.io
if [ -d "/Users/ryan/development/afterdark-meta-project/darkstorage.io" ]; then
  cp "$AUTHENTIK_DIR/config/services/darkstorage-io/.env.production" "/Users/ryan/development/afterdark-meta-project/darkstorage.io/.env.production" 2>/dev/null && echo "✅ darkstorage.io" || echo "⚠️  darkstorage.io - no .env"
fi

# afterdarksys.com
if [ -d "/Users/ryan/development/afterdark-meta-project/afterdarksys.com" ]; then
  cp "$AUTHENTIK_DIR/config/services/afterdarksys-com/.env.production" "/Users/ryan/development/afterdark-meta-project/afterdarksys.com/.env.production" 2>/dev/null && echo "✅ afterdarksys.com" || echo "⚠️  afterdarksys.com - no .env"
fi

# console.darkapi.io (check multiple locations)
if [ -d "/Users/ryan/development/console.darkapi.io" ]; then
  cp "$AUTHENTIK_DIR/config/services/console-darkapi-io/.env.production" "/Users/ryan/development/console.darkapi.io/.env.production" 2>/dev/null && echo "✅ console.darkapi.io" || echo "⚠️  console.darkapi.io - no .env"
fi

# model2go.com
if [ -d "/Users/ryan/development/model2go.com" ]; then
  cp "$AUTHENTIK_DIR/config/services/model2go-com/.env.production" "/Users/ryan/development/model2go.com/.env.production" 2>/dev/null && echo "✅ model2go.com" || echo "⚠️  model2go.com - no .env"
fi

echo "✅ Done!"
