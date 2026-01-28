#!/bin/bash
set -euo pipefail

###############################################################################
# Setup OAuth2 Applications for AfterDark Services
# Creates OAuth apps for all your services/sites
###############################################################################

CONTAINER="${AUTHENTIK_CONTAINER:-authentik-server-prod}"

# Colors
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[✓]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

# Create OAuth2 application
create_oauth_app() {
    local app_name=$1
    local app_slug=$2
    local client_id=$3
    local redirect_urls=$4
    local launch_url=$5

    log_info "Creating OAuth2 app: $app_name"

    docker exec "${CONTAINER}" python -m manage shell << PYTHON_EOF
from authentik.core.models import Application
from authentik.providers.oauth2.models import OAuth2Provider
from authentik.flows.models import Flow
from authentik.crypto.models import CertificateKeyPair

# Get or create OAuth2 provider
try:
    provider = OAuth2Provider.objects.get(name='${app_name} OAuth2 Provider')
    print(f"Provider exists: {provider.name}")
except OAuth2Provider.DoesNotExist:
    # Get default authorization flow
    auth_flow = Flow.objects.filter(designation='authorization').first()

    # Get self-signed certificate
    cert = CertificateKeyPair.objects.filter(name='authentik Self-signed Certificate').first()

    provider = OAuth2Provider.objects.create(
        name='${app_name} OAuth2 Provider',
        authorization_flow=auth_flow,
        client_id='${client_id}',
        client_type='confidential',
        redirect_uris='${redirect_urls}',
        signing_key=cert,
        sub_mode='hashed_user_id',
        include_claims_in_id_token=True
    )
    print(f"Created provider: {provider.name}")

# Get or create application
try:
    app = Application.objects.get(slug='${app_slug}')
    print(f"Application exists: {app.name}")
    app.provider = provider
    app.save()
except Application.DoesNotExist:
    app = Application.objects.create(
        name='${app_name}',
        slug='${app_slug}',
        provider=provider,
        meta_description='${app_name}',
        meta_launch_url='${launch_url}',
        open_in_new_tab=False
    )
    print(f"Created application: {app.name}")

print("SUCCESS")
print(f"Application: {app.slug}")
print(f"Client ID: {provider.client_id}")
print(f"Client Secret: {provider.client_secret[:30]}...")
print(f"Redirect URIs: {provider.redirect_uris}")
PYTHON_EOF

    log_success "$app_name configured"
}

# Main execution
main() {
    log_info "Setting up OAuth2 applications for AfterDark services..."
    echo ""

    # AfterDark Security Suite Main
    create_oauth_app \
        "AfterDark Security Suite" \
        "afterdark-security-suite" \
        "afterdark-security-suite" \
        "http://localhost:9090/oauth/callback
https://security.afterdark.local/oauth/callback" \
        "http://localhost:9090/"

    # AfterDark HTTP Proxy (ads-httpproxy)
    create_oauth_app \
        "AfterDark HTTP Proxy" \
        "ads-httpproxy" \
        "ads-httpproxy-client" \
        "http://localhost:8080/oauth/callback
https://proxy.afterdark.local/oauth/callback" \
        "http://localhost:9090/"

    # AfterDark Management Console
    create_oauth_app \
        "AfterDark Management Console" \
        "ads-management" \
        "ads-management-console" \
        "http://localhost:9100/oauth/callback
https://console.afterdark.local/oauth/callback" \
        "http://localhost:9100/"

    # Add more apps as needed...
    # create_oauth_app "Your App Name" "app-slug" "client-id" "redirect-urls" "launch-url"

    echo ""
    log_success "All OAuth2 applications configured!"
    echo ""
    echo "View applications at: http://localhost:9000/if/admin/#/core/applications"
    echo ""
    log_warn "Save client secrets securely! They won't be shown again."
}

# Interactive mode
if [ "${1:-}" = "--interactive" ]; then
    echo "=== Interactive OAuth2 App Creation ==="
    read -p "Application Name: " app_name
    read -p "Application Slug (kebab-case): " app_slug
    read -p "Client ID: " client_id
    read -p "Redirect URLs (newline separated, press Ctrl+D when done): " -d $'\004' redirect_urls
    echo ""
    read -p "Launch URL: " launch_url

    create_oauth_app "$app_name" "$app_slug" "$client_id" "$redirect_urls" "$launch_url"
    exit 0
fi

# Run main if executed directly
if [ "${BASH_SOURCE[0]}" = "${0}" ]; then
    main "$@"
fi
