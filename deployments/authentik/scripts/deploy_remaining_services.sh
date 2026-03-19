#!/bin/bash
# Deploy .env.production to all remaining services

set -e

AUTHENTIK_DIR="/Users/ryan/development/afterdark-meta-project/afterdark-security-suite/afterdark-darkd/deployments/authentik"

REMAINING_SERVICES=(
  "shipshack.io"
  "aiserve.farm"
  "lonely.fyi"
  "flipid.io"
  "petalarm.ai"
  "web3dns.io"
  "basebot.ai"
  "filehashes.io"
  "afterapps.io"
)

echo "🚀 Deploying .env.production to remaining services..."
echo ""

for service in "${REMAINING_SERVICES[@]}"; do
  SERVICE_SLUG="${service//./-}"
  SERVICE_DIR="/Users/ryan/development/$service"

  if [ ! -d "$SERVICE_DIR" ]; then
    echo "⚠️  $service - Directory not found, skipping"
    continue
  fi

  echo "📦 $service"

  if [ -f "$AUTHENTIK_DIR/config/services/$SERVICE_SLUG/.env.production" ]; then
    cp "$AUTHENTIK_DIR/config/services/$SERVICE_SLUG/.env.production" "$SERVICE_DIR/.env.production"
    echo "  ✅ Copied .env.production"
  else
    echo "  ⚠️  .env.production not found"
  fi
done

echo ""
echo "✅ Deployment complete!"
