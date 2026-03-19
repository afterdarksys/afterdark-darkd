#!/bin/bash
# Deploy OAuth to all Next.js services

set -e

AUTHENTIK_DIR="/Users/ryan/development/afterdark-meta-project/afterdark-security-suite/afterdark-darkd/deployments/authentik"
TEMPLATE_DIR="/Users/ryan/development/viralvisions.io"

NEXTJS_SERVICES=(
  "viralvisions.io"
  "aeims.app"
  "telcocloud.io"
  "cats.center"
  "dogs.institute"
)

echo "🚀 Deploying OAuth to Next.js services..."
echo ""

for service in "${NEXTJS_SERVICES[@]}"; do
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
  else
    echo "  ⚠️  .env.production not found for $SERVICE_SLUG"
  fi

  # 2. Create lib/auth directory if it doesn't exist
  mkdir -p "$SERVICE_DIR/lib/auth"

  # 3. Copy OAuth module
  if [ -f "$TEMPLATE_DIR/lib/auth/oauth.ts" ] && [ "$SERVICE_DIR" != "$TEMPLATE_DIR" ]; then
    cp "$TEMPLATE_DIR/lib/auth/oauth.ts" "$SERVICE_DIR/lib/auth/oauth.ts"
    echo "  ✅ Copied OAuth module"
  elif [ "$SERVICE_DIR" = "$TEMPLATE_DIR" ]; then
    echo "  ✅ OAuth module already exists (template service)"
  fi

  # 4. Create API routes
  mkdir -p "$SERVICE_DIR/app/api/auth/oauth/login"
  mkdir -p "$SERVICE_DIR/app/api/auth/oauth/callback"
  mkdir -p "$SERVICE_DIR/app/api/auth/oauth/logout"

  # Copy OAuth routes (skip if same directory)
  if [ "$SERVICE_DIR" != "$TEMPLATE_DIR" ]; then
    if [ -f "$TEMPLATE_DIR/app/api/auth/oauth/login/route.ts" ]; then
      cp "$TEMPLATE_DIR/app/api/auth/oauth/login/route.ts" "$SERVICE_DIR/app/api/auth/oauth/login/route.ts"
      echo "  ✅ Copied OAuth login route"
    fi

    if [ -f "$TEMPLATE_DIR/app/api/auth/oauth/callback/route.ts" ]; then
      cp "$TEMPLATE_DIR/app/api/auth/oauth/callback/route.ts" "$SERVICE_DIR/app/api/auth/oauth/callback/route.ts"
      echo "  ✅ Copied OAuth callback route"
    fi

    if [ -f "$TEMPLATE_DIR/app/api/auth/oauth/logout/route.ts" ]; then
      cp "$TEMPLATE_DIR/app/api/auth/oauth/logout/route.ts" "$SERVICE_DIR/app/api/auth/oauth/logout/route.ts"
      echo "  ✅ Copied OAuth logout route"
    fi
  else
    echo "  ✅ OAuth routes already exist (template service)"
  fi

  echo "  ✅ $service OAuth integration complete!"
  echo ""
done

echo "✅ OAuth deployment to Next.js services complete!"
echo ""
echo "Next steps:"
echo "  1. Review each service's login page and add SSO button"
echo "  2. Test OAuth flow on each service"
echo "  3. Deploy to production"
