#!/bin/bash
set -euo pipefail

###############################################################################
# Authentik Bootstrap Script
# Completely automates Authentik deployment and configuration from code
###############################################################################

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
DEPLOY_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
CONFIG_DIR="${DEPLOY_DIR}/config"
BLUEPRINTS_DIR="${DEPLOY_DIR}/blueprints"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
AUTHENTIK_URL="${AUTHENTIK_URL:-http://localhost:9000}"
AUTHENTIK_CONTAINER="${AUTHENTIK_CONTAINER:-authentik-server-prod}"
AUTHENTIK_ADMIN_USER="${AUTHENTIK_ADMIN_USER:-akadmin}"
AUTHENTIK_ADMIN_EMAIL="${AUTHENTIK_ADMIN_EMAIL:-admin@afterdark.local}"
AUTHENTIK_ADMIN_PASSWORD="${AUTHENTIK_ADMIN_PASSWORD:-AfterDark2026!}"

# Functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[✓]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[✗]${NC} $1"
}

check_dependencies() {
    log_info "Checking dependencies..."

    local missing_deps=()

    command -v docker >/dev/null 2>&1 || missing_deps+=("docker")
    command -v curl >/dev/null 2>&1 || missing_deps+=("curl")
    command -v jq >/dev/null 2>&1 || missing_deps+=("jq")
    command -v python3 >/dev/null 2>&1 || missing_deps+=("python3")

    if [ ${#missing_deps[@]} -ne 0 ]; then
        log_error "Missing dependencies: ${missing_deps[*]}"
        exit 1
    fi

    log_success "All dependencies installed"
}

wait_for_authentik() {
    log_info "Waiting for Authentik to be ready..."

    local max_attempts=30
    local attempt=1

    while [ $attempt -le $max_attempts ]; do
        if curl -s -o /dev/null -w "%{http_code}" "${AUTHENTIK_URL}/api/v3/" | grep -q "200\|401\|403"; then
            log_success "Authentik is ready!"
            return 0
        fi

        echo -n "."
        sleep 2
        ((attempt++))
    done

    log_error "Authentik did not become ready in time"
    return 1
}

create_admin_user() {
    log_info "Creating/resetting admin user: ${AUTHENTIK_ADMIN_USER}"

    # Create admin user via Django shell
    docker exec "${AUTHENTIK_CONTAINER}" python -m manage shell << PYTHON_EOF
from authentik.core.models import User
from authentik.core.models import Group

# Create or update admin user
try:
    user = User.objects.get(username='${AUTHENTIK_ADMIN_USER}')
    print(f"User {user.username} already exists, updating...")
except User.DoesNotExist:
    user = User.objects.create(
        username='${AUTHENTIK_ADMIN_USER}',
        email='${AUTHENTIK_ADMIN_EMAIL}',
        name='AfterDark Administrator',
        is_active=True
    )
    print(f"Created user: {user.username}")

# Set password
user.set_password('${AUTHENTIK_ADMIN_PASSWORD}')
user.is_superuser = True
user.save()

# Add to admins group
try:
    admin_group = Group.objects.get(name='authentik Admins')
    user.ak_groups.add(admin_group)
    print(f"Added {user.username} to authentik Admins group")
except Group.DoesNotExist:
    print("Admin group not found, user created as superuser")

print(f"SUCCESS: Admin user ready - {user.username} ({user.email})")
PYTHON_EOF

    log_success "Admin user configured"
}

create_api_token() {
    log_info "Creating persistent API token..."

    # Create API token via Django shell
    TOKEN=$(docker exec "${AUTHENTIK_CONTAINER}" python -m manage shell << 'PYTHON_EOF' 2>/dev/null | tail -1
from authentik.core.models import User, Token, TokenIntents

user = User.objects.get(username='${AUTHENTIK_ADMIN_USER}')

# Remove old tokens with same identifier
Token.objects.filter(identifier='bootstrap-automation-token').delete()

# Create new token
token = Token.objects.create(
    identifier='bootstrap-automation-token',
    user=user,
    intent=TokenIntents.INTENT_API,
    expiring=False,
    description='Bootstrap automation token (never expires)'
)

print(token.key)
PYTHON_EOF
)

    if [ -z "$TOKEN" ]; then
        log_error "Failed to create API token"
        return 1
    fi

    # Save token to .env file
    mkdir -p "${DEPLOY_DIR}"
    echo "AUTHENTIK_TOKEN=${TOKEN}" > "${DEPLOY_DIR}/.env"
    echo "AUTHENTIK_URL=${AUTHENTIK_URL}" >> "${DEPLOY_DIR}/.env"
    echo "AUTHENTIK_ADMIN_USER=${AUTHENTIK_ADMIN_USER}" >> "${DEPLOY_DIR}/.env"

    log_success "API token created and saved to ${DEPLOY_DIR}/.env"
    echo "   Token: ${TOKEN:0:20}..."

    export AUTHENTIK_TOKEN="${TOKEN}"
}

apply_blueprints() {
    log_info "Applying custom blueprints..."

    if [ ! -d "${BLUEPRINTS_DIR}" ]; then
        log_warn "No blueprints directory found at ${BLUEPRINTS_DIR}"
        return 0
    fi

    # Copy blueprints into container
    local blueprint_files=($(find "${BLUEPRINTS_DIR}" -name "*.yaml" -o -name "*.yml"))

    if [ ${#blueprint_files[@]} -eq 0 ]; then
        log_warn "No blueprint files found"
        return 0
    fi

    # Create custom directory in container
    docker exec "${AUTHENTIK_CONTAINER}" mkdir -p /tmp/blueprints 2>/dev/null || true

    for blueprint_file in "${blueprint_files[@]}"; do
        local filename=$(basename "$blueprint_file")
        log_info "Skipping blueprint: ${filename} (apply manually via UI after bootstrap)"

        # Just copy to temp location for reference
        docker cp "${blueprint_file}" "${AUTHENTIK_CONTAINER}:/tmp/blueprints/${filename}" 2>/dev/null || true
    done

    log_warn "Blueprints copied to /tmp/blueprints/ - apply manually via Authentik UI"
}

export_current_config() {
    log_info "Exporting current configuration..."

    if [ ! -f "${SCRIPT_DIR}/authentik_client.py" ]; then
        log_error "authentik_client.py not found"
        return 1
    fi

    # Make sure we have the token
    if [ -z "${AUTHENTIK_TOKEN:-}" ]; then
        log_warn "No API token available, skipping export"
        return 0
    fi

    python3 "${SCRIPT_DIR}/authentik_client.py" \
        --url "${AUTHENTIK_URL}" \
        --token "${AUTHENTIK_TOKEN}" \
        export \
        --output "${CONFIG_DIR}"

    log_success "Configuration exported to ${CONFIG_DIR}"
}

create_oauth2_application() {
    log_info "Creating AfterDark OAuth2 application..."

    # Create OAuth2 provider and application via Django shell
    docker exec "${AUTHENTIK_CONTAINER}" python -m manage shell << 'PYTHON_EOF'
from authentik.core.models import Application
from authentik.providers.oauth2.models import OAuth2Provider
from authentik.flows.models import Flow
from authentik.crypto.models import CertificateKeyPair

# Get or create OAuth2 provider
try:
    provider = OAuth2Provider.objects.get(name='AfterDark OAuth2 Provider')
    print(f"Provider exists: {provider.name}")
except OAuth2Provider.DoesNotExist:
    # Get default authorization flow
    auth_flow = Flow.objects.filter(designation='authorization').first()

    # Get self-signed certificate
    cert = CertificateKeyPair.objects.filter(name='authentik Self-signed Certificate').first()

    provider = OAuth2Provider.objects.create(
        name='AfterDark OAuth2 Provider',
        authorization_flow=auth_flow,
        client_id='afterdark-security-suite',
        client_type='confidential',
        redirect_uris='http://localhost:9090/oauth/callback\nhttp://localhost:8080/oauth/callback',
        signing_key=cert,
        sub_mode='hashed_user_id',
        include_claims_in_id_token=True
    )
    print(f"Created provider: {provider.name}")
    print(f"Client ID: {provider.client_id}")
    print(f"Client Secret: {provider.client_secret}")

# Get or create application
try:
    app = Application.objects.get(slug='afterdark-security-suite')
    print(f"Application exists: {app.name}")
except Application.DoesNotExist:
    app = Application.objects.create(
        name='AfterDark Security Suite',
        slug='afterdark-security-suite',
        provider=provider,
        meta_description='AfterDark Security Suite main application',
        meta_launch_url='http://localhost:9090/',
        open_in_new_tab=False
    )
    print(f"Created application: {app.name}")

print("SUCCESS")
print(f"Application: {app.slug}")
print(f"Provider Client ID: {provider.client_id}")
print(f"Provider Client Secret: {provider.client_secret[:20]}...")
PYTHON_EOF

    log_success "OAuth2 application configured"
}

show_summary() {
    echo ""
    echo "================================================================"
    log_success "Authentik Bootstrap Complete!"
    echo "================================================================"
    echo ""
    echo "Authentik URL:       ${AUTHENTIK_URL}"
    echo "Admin Username:      ${AUTHENTIK_ADMIN_USER}"
    echo "Admin Password:      ${AUTHENTIK_ADMIN_PASSWORD}"
    echo ""
    echo "Configuration saved to: ${DEPLOY_DIR}/.env"
    echo "Exported config in:     ${CONFIG_DIR}"
    echo ""
    echo "Next steps:"
    echo "  1. Open Authentik UI: ${AUTHENTIK_URL}"
    echo "  2. Login with credentials above"
    echo "  3. Review OAuth2 application: AfterDark Security Suite"
    echo "  4. Export config: ./scripts/authentik_client.py export"
    echo ""
    echo "================================================================"
}

# Main execution
main() {
    log_info "Starting Authentik bootstrap..."

    check_dependencies
    wait_for_authentik
    create_admin_user
    create_api_token
    create_oauth2_application
    apply_blueprints
    export_current_config
    show_summary
}

# Run main if executed directly
if [ "${BASH_SOURCE[0]}" = "${0}" ]; then
    main "$@"
fi
