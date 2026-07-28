#!/bin/bash
# Deploy OAuth to all PHP services

set -e

AUTHENTIK_DIR="/Users/ryan/development/afterdark-meta-project/afterdark-security-suite/afterdark-darkd/deployments/authentik"
TEMPLATE_DIR="/Users/ryan/development/veribits.com"

PHP_SERVICES=(
  "veribits.com"
  "purrr.love"
  "purrr.me"
)

echo "🚀 Deploying OAuth to PHP services..."
echo ""

for service in "${PHP_SERVICES[@]}"; do
  SERVICE_SLUG="${service//./-}"
  SERVICE_DIR="/Users/ryan/development/$service"

  if [ ! -d "$SERVICE_DIR" ]; then
    echo "⚠️  $service - Directory not found, skipping"
    continue
  fi

  echo "📦 Processing $service..."

  # 1. Merge .env.production (append to existing)
  if [ -f "$AUTHENTIK_DIR/config/services/$SERVICE_SLUG/.env.production" ]; then
    cat "$AUTHENTIK_DIR/config/services/$SERVICE_SLUG/.env.production" >> "$SERVICE_DIR/.env.production"
    echo "  ✅ Merged OAuth config to .env.production"
  else
    echo "  ⚠️  .env.production not found for $SERVICE_SLUG"
  fi

  # 2. Create Auth directory
  mkdir -p "$SERVICE_DIR/app/src/Auth"

  # 3. Copy OAuth class (skip if same directory)
  if [ "$SERVICE_DIR" != "$TEMPLATE_DIR" ] && [ -f "$TEMPLATE_DIR/app/src/Auth/OAuth.php" ]; then
    # Adapt namespace for each service
    SERVICE_NAME=$(echo "$service" | sed 's/\.com//;s/\.love//;s/\.me//' | sed 's/\b\(.\)/\u\1/g')
    sed "s/VeriBits/$SERVICE_NAME/g" "$TEMPLATE_DIR/app/src/Auth/OAuth.php" > "$SERVICE_DIR/app/src/Auth/OAuth.php"
    echo "  ✅ Copied OAuth class (namespace: $SERVICE_NAME)"
  elif [ "$SERVICE_DIR" = "$TEMPLATE_DIR" ]; then
    echo "  ✅ OAuth class already exists (template service)"
  fi

  # 4. Create public directory if doesn't exist
  mkdir -p "$SERVICE_DIR/public"

  # 5. Copy OAuth endpoints (skip if same directory)
  if [ "$SERVICE_DIR" != "$TEMPLATE_DIR" ]; then
    if [ -f "$TEMPLATE_DIR/public/oauth_login.php" ]; then
      sed "s/VeriBits/$SERVICE_NAME/g" "$TEMPLATE_DIR/public/oauth_login.php" > "$SERVICE_DIR/public/oauth_login.php"
      echo "  ✅ Copied OAuth login endpoint"
    fi

    if [ -f "$TEMPLATE_DIR/public/oauth_callback.php" ]; then
      sed "s/VeriBits/$SERVICE_NAME/g" "$TEMPLATE_DIR/public/oauth_callback.php" > "$SERVICE_DIR/public/oauth_callback.php"
      echo "  ✅ Copied OAuth callback endpoint"
    fi

    if [ -f "$TEMPLATE_DIR/public/oauth_logout.php" ]; then
      sed "s/VeriBits/$SERVICE_NAME/g" "$TEMPLATE_DIR/public/oauth_logout.php" > "$SERVICE_DIR/public/oauth_logout.php"
      echo "  ✅ Copied OAuth logout endpoint"
    fi
  else
    echo "  ✅ OAuth endpoints already exist (template service)"
  fi

  echo "  ✅ $service OAuth integration complete!"
  echo ""
done

echo "✅ OAuth deployment to PHP services complete!"
