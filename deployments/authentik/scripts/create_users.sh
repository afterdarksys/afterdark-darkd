#!/bin/bash
set -euo pipefail

###############################################################################
# Create AfterDark User Accounts
# Creates real user accounts for your team/clients
###############################################################################

CONTAINER="${AUTHENTIK_CONTAINER:-authentik-server-prod}"

# Colors
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[✓]${NC} $1"
}

# Create a user
create_user() {
    local username=$1
    local email=$2
    local password=$3
    local name=$4

    log_info "Creating user: $username ($email)"

    docker exec "${CONTAINER}" python -m manage shell << PYTHON_EOF
from authentik.core.models import User
from authentik.core.models import Group

try:
    user = User.objects.get(username='${username}')
    print(f"User {user.username} already exists, updating...")
    user.email = '${email}'
    user.name = '${name}'
except User.DoesNotExist:
    user = User.objects.create(
        username='${username}',
        email='${email}',
        name='${name}',
        is_active=True
    )
    print(f"Created user: {user.username}")

# Set password
user.set_password('${password}')
user.save()

# Add to default users group
try:
    users_group = Group.objects.get(name='authentik Users')
    user.ak_groups.add(users_group)
    print(f"Added {user.username} to Users group")
except Group.DoesNotExist:
    print("Users group not found")

print(f"SUCCESS: {user.username} ({user.email})")
PYTHON_EOF

    log_success "User $username created"
}

# Main execution
main() {
    log_info "Creating AfterDark user accounts..."
    echo ""

    # Example users - customize these!
    create_user "john.doe" "john@afterdark.local" "TempPass123!" "John Doe"
    create_user "jane.smith" "jane@afterdark.local" "TempPass123!" "Jane Smith"
    create_user "dev.user" "dev@afterdark.local" "TempPass123!" "Development User"
    create_user "test.user" "test@afterdark.local" "TempPass123!" "Test User"

    echo ""
    log_success "All users created!"
    echo ""
    echo "Users can now login at: http://localhost:9000"
    echo "Default password: TempPass123! (users should change on first login)"
}

# Interactive mode
if [ "${1:-}" = "--interactive" ]; then
    echo "=== Interactive User Creation ==="
    read -p "Username: " username
    read -p "Email: " email
    read -p "Full Name: " name
    read -s -p "Password: " password
    echo ""

    create_user "$username" "$email" "$password" "$name"
    exit 0
fi

# Run main if executed directly
if [ "${BASH_SOURCE[0]}" = "${0}" ]; then
    main "$@"
fi
