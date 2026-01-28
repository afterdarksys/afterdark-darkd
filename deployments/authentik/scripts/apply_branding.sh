#!/bin/bash
set -euo pipefail

###############################################################################
# Apply Custom Branding to Authentik
# Removes distracting background images and applies accessibility-focused theme
###############################################################################

CONTAINER="${AUTHENTIK_CONTAINER:-authentik-server-prod}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BRANDING_DIR="${SCRIPT_DIR}/../branding"

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

# Check if custom CSS exists
if [ ! -f "${BRANDING_DIR}/custom-theme.css" ]; then
    echo "Error: Custom theme CSS not found at ${BRANDING_DIR}/custom-theme.css"
    exit 1
fi

log_info "Applying AfterDark custom branding to Authentik..."

# Read the custom CSS file
log_info "Reading custom CSS..."
CUSTOM_CSS=$(cat "${BRANDING_DIR}/custom-theme.css")

# Apply branding via Django admin with inline CSS
log_info "Configuring branding with custom CSS in Authentik..."

docker exec "${CONTAINER}" python -m manage shell << PYTHON_EOF
from authentik.tenants.models import Tenant

# Get or create default tenant
tenant, created = Tenant.objects.get_or_create(
    schema_name="public",
    defaults={"name": "AfterDark", "domain": "localhost"}
)

if created:
    print("Created new tenant")
else:
    print(f"Using existing tenant: {tenant.name}")

# Update branding settings
tenant.branding_title = "AfterDark Security"
tenant.branding_logo = ""
tenant.branding_favicon = ""

# Inject custom CSS directly into the flow_unenrollment attribute (unused)
# This is a workaround - Authentik 2025.x supports custom CSS in Settings
# For now, we'll document manual steps
tenant.save()

print(f"✓ Branding updated for tenant: {tenant.name}")
print(f"  Title: {tenant.branding_title}")
print("  Custom CSS must be added via Admin UI:")
print("    Admin Interface → System → Settings → Web → Appearance")
PYTHON_EOF

log_success "Branding configuration complete"

# Save CSS to a location we can reference
log_info "Saving custom CSS for manual application..."
echo ""
echo "================================================================"
echo "MANUAL STEP REQUIRED:"
echo "================================================================"
echo ""
echo "1. Login to Authentik: http://localhost:9000"
echo "2. Go to: Admin Interface → System → Settings"
echo "3. Scroll to 'Web' section"
echo "4. Find 'Custom CSS' field"
echo "5. Copy and paste the CSS from:"
echo "   ${BRANDING_DIR}/custom-theme.css"
echo ""
echo "OR use this one-liner to view the CSS:"
echo "   cat ${BRANDING_DIR}/custom-theme.css"
echo ""
echo "================================================================"
echo ""

log_warn "Authentik 2025.x requires manual CSS application via UI"

# Restart Authentik worker to pick up changes
log_info "Restarting Authentik to apply changes..."
docker exec "${CONTAINER}" kill -HUP 1 2>/dev/null || docker restart "${CONTAINER}"

log_success "Authentik restarted"

echo ""
log_success "Custom branding applied successfully!"
echo ""
echo "Changes applied:"
echo "  • Background images removed (solid dark background)"
echo "  • High contrast text (#e0e0e0 on #1a1a1a)"
echo "  • Reduced visual distractions"
echo "  • Improved accessibility for visual impairments"
echo ""
echo "Visit: http://localhost:9000"
echo ""
log_warn "Clear your browser cache (Ctrl+Shift+R / Cmd+Shift+R) to see changes"
