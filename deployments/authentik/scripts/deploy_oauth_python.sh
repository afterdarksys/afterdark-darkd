#!/bin/bash
# Deploy OAuth to all Python/FastAPI services

set -e

AUTHENTIK_DIR="/Users/ryan/development/afterdark-meta-project/afterdark-security-suite/afterdark-darkd/deployments/authentik"
TEMPLATE_DIR="/Users/ryan/development/promptery.io"

PYTHON_SERVICES=(
  "promptery.io"
  "flipdomain.io"
  "itz.agency"
  "onedns.io"
  "betterphish.io"
)

echo "🚀 Deploying OAuth to Python services..."
echo ""

for service in "${PYTHON_SERVICES[@]}"; do
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

  # 2. Create auth directory
  mkdir -p "$SERVICE_DIR/app/auth"
  mkdir -p "$SERVICE_DIR/app/routes"

  # 3. Copy OAuth module (skip if same directory)
  if [ "$SERVICE_DIR" != "$TEMPLATE_DIR" ] && [ -f "$TEMPLATE_DIR/app/auth/oauth.py" ]; then
    cp "$TEMPLATE_DIR/app/auth/oauth.py" "$SERVICE_DIR/app/auth/oauth.py"
    echo "  ✅ Copied OAuth module"
  elif [ "$SERVICE_DIR" = "$TEMPLATE_DIR" ]; then
    echo "  ✅ OAuth module already exists (template service)"
  fi

  # 4. Copy OAuth routes (skip if same directory)
  if [ "$SERVICE_DIR" != "$TEMPLATE_DIR" ] && [ -f "$TEMPLATE_DIR/app/routes/oauth.py" ]; then
    cp "$TEMPLATE_DIR/app/routes/oauth.py" "$SERVICE_DIR/app/routes/oauth.py"
    echo "  ✅ Copied OAuth routes"
  elif [ "$SERVICE_DIR" = "$TEMPLATE_DIR" ]; then
    echo "  ✅ OAuth routes already exist (template service)"
  fi

  # 5. Add httpx dependency if not present
  if [ -f "$SERVICE_DIR/requirements.txt" ]; then
    if ! grep -q "httpx" "$SERVICE_DIR/requirements.txt"; then
      echo "httpx>=0.26.0" >> "$SERVICE_DIR/requirements.txt"
      echo "  ✅ Added httpx dependency"
    fi
  fi

  echo "  ✅ $service OAuth integration complete!"
  echo ""
done

echo "✅ OAuth deployment to Python services complete!"
