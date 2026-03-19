#!/bin/bash
# Deploy OAuth to Node.js/Express services

set -e

AUTHENTIK_DIR="/Users/ryan/development/afterdark-meta-project/afterdark-security-suite/afterdark-darkd/deployments/authentik"

NODEJS_SERVICES=(
  "computeapi.io"
  "systemapi.io"
  "llmsecurity.dev"
)

echo "🚀 Deploying OAuth to Node.js services..."
echo ""

for service in "${NODEJS_SERVICES[@]}"; do
  SERVICE_SLUG="${service//./-}"
  SERVICE_DIR="/Users/ryan/development/$service"

  if [ ! -d "$SERVICE_DIR" ]; then
    echo "⚠️  $service - Directory not found, skipping"
    continue
  fi

  echo "📦 Processing $service..."

  # 1. Copy .env.production
  if [ -f "$AUTHENTIK_DIR/config/services/$SERVICE_SLUG/.env.production" ]; then
    cp "$AUTHENTIK_DIR/config/services/$SERVICE_SLUG/.env.production" "$SERVICE_DIR/.env.production"
    echo "  ✅ Copied .env.production"
  fi

  # 2. Add dependencies to package.json
  cd "$SERVICE_DIR"
  if [ -f "package.json" ]; then
    npm install openid-client express-session dotenv --save 2>&1 | tail -2
    echo "  ✅ Installed OAuth dependencies"
  fi

  echo "  ✅ $service OAuth deps complete!"
  echo ""
done

echo "✅ OAuth deployment to Node.js services complete!"
echo ""
echo "Note: You'll need to manually add OAuth routes to each Express app"
