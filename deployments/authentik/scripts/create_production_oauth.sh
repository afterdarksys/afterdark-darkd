#!/bin/bash
#
# Create OAuth Providers for All Production Domains
#
# This script creates 29 OAuth providers for all public-facing AfterDark domains.
# Uses adsyslib for reliable Django ORM-based provider creation.
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_DIR="$(dirname "$SCRIPT_DIR")/config"
ADSYSLIB_PATH="/Users/ryan/development/adsyslib"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  AfterDark Production OAuth Provider Setup"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo

# Check if adsyslib is installed
if ! python3 -c "import adsyslib" 2>/dev/null; then
    echo -e "${YELLOW}⚠ adsyslib not found. Installing...${NC}"
    pip install -e "$ADSYSLIB_PATH" || {
        echo -e "${RED}✗ Failed to install adsyslib${NC}"
        exit 1
    }
    echo -e "${GREEN}✓ adsyslib installed${NC}"
fi

# Check if Authentik container is running
if ! docker ps | grep -q authentik-server; then
    echo -e "${RED}✗ Authentik container not running${NC}"
    echo "  Start Authentik first: cd deployments/authentik && docker-compose up -d"
    exit 1
fi

echo -e "${GREEN}✓ Authentik container is running${NC}"
echo

# Count domains in config
DOMAIN_COUNT=$(python3 -c "import json; print(len(json.load(open('$CONFIG_DIR/production_domains.json'))['apps']))")
echo "📋 Found $DOMAIN_COUNT production domains in config"
echo

# Show categories
echo "Categories:"
python3 << EOF
import json
with open('$CONFIG_DIR/production_domains.json') as f:
    data = json.load(f)
    categories = {}
    for app in data['apps']:
        cat = app.get('category', 'unknown')
        categories[cat] = categories.get(cat, 0) + 1

    for cat, count in sorted(categories.items()):
        print(f"  {cat.capitalize()}: {count}")
EOF
echo

# Confirm before proceeding
read -p "Create OAuth providers for all $DOMAIN_COUNT domains? (y/N) " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo "Cancelled."
    exit 0
fi

echo
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  Creating OAuth Providers..."
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo

# Create providers using adsyslib
adsys authentik oauth-bulk-create \
    "$CONFIG_DIR/production_domains.json" \
    --output-env "$CONFIG_DIR/.env.production" \
    --output-json "$CONFIG_DIR/production_oauth_secrets.json" \
    --container authentik-server-prod

echo
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  ✓ OAuth Provider Creation Complete"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo

# Show summary
echo "📊 Summary:"
echo "  • Created: $DOMAIN_COUNT OAuth providers"
echo "  • Credentials saved to: config/.env.production"
echo "  • Secrets JSON: config/production_oauth_secrets.json"
echo

# Security reminder
echo -e "${YELLOW}⚠ Security Reminder:${NC}"
echo "  • .env.production contains production secrets"
echo "  • DO NOT commit to git (already in .gitignore)"
echo "  • Store securely (vault, password manager, etc.)"
echo "  • Use different secrets for dev vs prod"
echo

# List created providers
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  Created OAuth Providers:"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
adsys authentik oauth-list --container authentik-server-prod

echo
echo -e "${GREEN}✓ Setup complete!${NC}"
echo
echo "Next steps:"
echo "  1. Verify DNS records for all domains"
echo "  2. Set up SSL certificates (Let's Encrypt recommended)"
echo "  3. Configure reverse proxy (Nginx/Traefik)"
echo "  4. Deploy OAuth middleware to each service"
echo "  5. Test SSO login flow for each domain"
echo
