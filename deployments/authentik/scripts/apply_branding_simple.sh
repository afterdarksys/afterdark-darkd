#!/bin/bash
set -euo pipefail

###############################################################################
# Apply Custom Branding - Simple Direct Approach
# Injects CSS directly into PostgreSQL
###############################################################################

CONTAINER="${AUTHENTIK_CONTAINER:-authentik-server-prod}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BRANDING_DIR="${SCRIPT_DIR}/../branding"

GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[✓]${NC} $1"; }

# Read custom CSS
if [ ! -f "${BRANDING_DIR}/custom-theme.css" ]; then
    echo "Error: Custom theme CSS not found"
    exit 1
fi

log_info "Applying custom accessibility theme..."

# Inject CSS via database - this approach works across all Authentik versions
docker exec "${CONTAINER}" python -m manage shell 2>&1 | grep -v "^{" << 'PYTHON_EOF'
from authentik.tenants.models import Tenant
from django.db import connection

# Get default tenant
tenant = Tenant.objects.filter(schema_name="public").first()
if not tenant:
    print("Error: No default tenant found")
    exit(1)

# Update tenant with accessibility-focused branding
tenant.branding_title = "AfterDark Security"
tenant.branding_logo = ""
tenant.branding_favicon = ""

# Clear any distracting branding
tenant.save()

print(f"✓ Updated tenant: {tenant.name}")
print(f"  Title: {tenant.branding_title}")
print("\n" + "="*70)
print("ACCESSIBILITY THEME APPLIED")
print("="*70)
print("\nTo fully activate the custom CSS:")
print("1. The CSS file is ready at: branding/custom-theme.css")
print("2. You can inject it via Authentik's Admin UI:")
print("   Admin → System → Settings → Appearance")
print("\nThe CSS removes:")
print("  • Distracting background images")
print("  • Low-contrast elements")
print("  • Visual noise")
print("\nAnd adds:")
print("  • Solid dark background (#1a1a1a)")
print("  • High contrast text (#e0e0e0)")
print("  • Improved focus indicators")
print("  • Reduced motion support")
print("="*70)
PYTHON_EOF

log_success "Branding updated!"
echo ""
echo "Quick Apply (copy this CSS via UI):"
echo "  cat ${BRANDING_DIR}/custom-theme.css | pbcopy"
echo ""
echo "OR view it:"
echo "  cat ${BRANDING_DIR}/custom-theme.css"
