#!/usr/bin/env python3
"""
Generate individual .env.production files for each service.

Reads production_oauth_secrets.json and creates a dedicated .env.production
file for each of the 29 services in config/services/<service-slug>/.env.production
"""

import json
import os
import secrets
from pathlib import Path
from datetime import datetime

def generate_session_secret(length=32):
    """Generate a random session secret."""
    return secrets.token_urlsafe(length)

def slug_to_env_prefix(slug):
    """Convert slug like 'viralvisions-io' to 'VIRALVISIONS_IO'."""
    return slug.replace('-', '_').upper()

def main():
    # Paths
    script_dir = Path(__file__).parent
    config_dir = script_dir.parent / "config"
    secrets_file = config_dir / "production_oauth_secrets.json"
    domains_file = config_dir / "production_domains.json"
    services_dir = config_dir / "services"

    # Load production secrets
    print(f"📖 Reading secrets from {secrets_file}")
    with open(secrets_file, 'r') as f:
        secrets_data = json.load(f)

    # Load production domains (has redirect_uris)
    print(f"📖 Reading domains from {domains_file}")
    with open(domains_file, 'r') as f:
        domains_data = json.load(f)['apps']

    # Create a mapping of client_id -> domain info
    domain_map = {app['client_id']: app for app in domains_data}

    # Create services directory
    services_dir.mkdir(exist_ok=True)
    print(f"📁 Creating service directories in {services_dir}")

    created_count = 0

    for app in secrets_data:
        app_slug = app['app_slug']
        client_id = app['client_id']
        client_secret = app['client_secret']
        client_type = app['client_type']
        app_name = app['app_name']
        category = app.get('category', 'general')

        # Get domain info (redirect URIs, description, etc.)
        domain_info = domain_map.get(client_id, {})
        redirect_uris = domain_info.get('redirect_uris', [])
        description = domain_info.get('description', '')

        # Create service directory
        service_dir = services_dir / app_slug
        service_dir.mkdir(exist_ok=True)

        # Primary redirect URI (first one)
        primary_redirect = redirect_uris[0] if redirect_uris else f"https://{app_slug.replace('-', '.')}/oauth/callback"

        # Extract domain from redirect URI
        domain = primary_redirect.replace('https://', '').replace('http://', '').split('/')[0]

        # Generate session secret
        session_secret = generate_session_secret()

        # Create .env.production content
        env_content = f"""# ============================================================
# {app_name.upper()} - OAuth Configuration
# ============================================================
# Service: {app_name}
# Domain: {domain}
# Category: {category}
# Description: {description}
# Generated: {datetime.now().isoformat()}
# ============================================================

# Authentik OAuth Configuration
AUTHENTIK_URL=https://auth.afterdarksys.com
AUTHENTIK_ISSUER=https://auth.afterdarksys.com/application/o/{client_id}/
AUTHENTIK_CLIENT_ID={client_id}
AUTHENTIK_CLIENT_SECRET={client_secret}
AUTHENTIK_CLIENT_TYPE={client_type}
AUTHENTIK_REDIRECT_URI={primary_redirect}

# OAuth Scopes
AUTHENTIK_SCOPES=openid,profile,email,groups,offline_access

# Session Configuration
SESSION_SECRET={session_secret}
SESSION_COOKIE_NAME={app_slug}_session
SESSION_COOKIE_SECURE=true
SESSION_COOKIE_HTTPONLY=true
SESSION_COOKIE_SAMESITE=lax
SESSION_MAX_AGE=86400

# Application Configuration
APP_NAME={app_name}
APP_DOMAIN={domain}
APP_URL=https://{domain}

# Development Override (set to 'true' for local dev)
# DEV_MODE=false
# DEV_REDIRECT_URI=http://localhost:3000/oauth/callback

# ============================================================
# SECURITY WARNING: Keep this file secure and never commit it!
# ============================================================
"""

        # Write .env.production file
        env_file = service_dir / ".env.production"
        with open(env_file, 'w') as f:
            f.write(env_content)

        print(f"  ✅ {app_slug:30} → {env_file}")
        created_count += 1

    print(f"\n✅ Generated {created_count} service .env files")
    print(f"📁 Location: {services_dir}")
    print(f"\n📋 Next Steps:")
    print(f"  1. Review generated .env files in config/services/*/")
    print(f"  2. Copy each .env.production to corresponding service directory")
    print(f"  3. Deploy OAuth middleware to each service")
    print(f"  4. Test OAuth flow on each domain")

    # Create a deployment script helper
    deploy_script = services_dir.parent / "deploy_env_files.sh"
    with open(deploy_script, 'w') as f:
        f.write("""#!/bin/bash
# Deploy .env.production files to all services
# Usage: ./deploy_env_files.sh [service-name]
#        ./deploy_env_files.sh all

set -e

CONFIG_DIR="$(cd "$(dirname "$0")" && pwd)"
SERVICES_DIR="$CONFIG_DIR/services"

if [ "$1" = "all" ]; then
    echo "🚀 Deploying .env files to all services..."
    for service_dir in "$SERVICES_DIR"/*; do
        if [ -d "$service_dir" ]; then
            service_name=$(basename "$service_dir")
            echo "  📦 $service_name"
            # TODO: Add your deployment command here
            # Example: scp "$service_dir/.env.production" user@server:/app/.env.production
        fi
    done
elif [ -n "$1" ]; then
    service_dir="$SERVICES_DIR/$1"
    if [ -d "$service_dir" ]; then
        echo "🚀 Deploying .env for $1..."
        # TODO: Add your deployment command here
    else
        echo "❌ Service '$1' not found"
        exit 1
    fi
else
    echo "Usage: $0 [service-name|all]"
    echo ""
    echo "Available services:"
    ls -1 "$SERVICES_DIR"
fi
""")

    os.chmod(deploy_script, 0o755)
    print(f"\n🔧 Created deployment helper: {deploy_script}")

if __name__ == "__main__":
    main()
