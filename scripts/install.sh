#!/bin/bash
#
# Install script for AfterDark-DarkD
# After Dark Systems, LLC
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

info() { echo -e "${GREEN}[INFO]${NC} $1"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1"; exit 1; }

# Check root
[[ $EUID -ne 0 ]] && error "This script must be run as root"

# Detect OS
detect_os() {
    case "$(uname -s)" in
        Linux*)
            if [[ -f /etc/os-release ]]; then
                . /etc/os-release
                echo "$ID"
            else
                echo "linux"
            fi
            ;;
        Darwin*)
            echo "macos"
            ;;
        *)
            error "Unsupported operating system"
            ;;
    esac
}

OS=$(detect_os)
info "Detected OS: $OS"

# Create user and directories
setup_directories() {
    info "Creating directories..."

    mkdir -p /etc/afterdark
    mkdir -p /var/lib/afterdark/data
    mkdir -p /var/log/afterdark
    mkdir -p /var/run/afterdark

    if [[ "$OS" != "macos" ]]; then
        # Create system user on Linux
        if ! id afterdark &>/dev/null; then
            useradd --system --no-create-home --shell /sbin/nologin afterdark
        fi
        chown -R afterdark:afterdark /var/lib/afterdark /var/log/afterdark /var/run/afterdark
    fi
}

# Install binaries
install_binaries() {
    info "Installing binaries..."

    cd "$PROJECT_ROOT"

    if [[ ! -f afterdark-darkd ]]; then
        info "Building binaries..."
        make build
    fi

    install -m 755 afterdark-darkd /usr/local/bin/
    install -m 755 afterdark-darkdadm /usr/local/bin/
    install -m 755 darkapi /usr/local/bin/
}

# Install config
install_config() {
    info "Installing configuration..."

    if [[ ! -f /etc/afterdark/darkd.yaml ]]; then
        cp "$PROJECT_ROOT/configs/darkd.yaml.example" /etc/afterdark/darkd.yaml
        chmod 640 /etc/afterdark/darkd.yaml
        [[ "$OS" != "macos" ]] && chown afterdark:afterdark /etc/afterdark/darkd.yaml
    else
        warn "Configuration already exists, skipping"
    fi
}

# Install service
install_service_linux() {
    info "Installing systemd service..."

    cat > /etc/systemd/system/afterdark-darkd.service <<EOF
[Unit]
Description=After Dark Systems Endpoint Security Daemon
Documentation=https://docs.afterdarksys.com/darkd
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=afterdark
Group=afterdark
ExecStart=/usr/local/bin/afterdark-darkd --config /etc/afterdark/darkd.yaml
ExecReload=/bin/kill -HUP \$MAINPID
Restart=always
RestartSec=10

NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
ReadWritePaths=/var/lib/afterdark /var/log/afterdark /var/run/afterdark

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable afterdark-darkd
}

install_service_macos() {
    info "Installing launchd service..."

    cat > /Library/LaunchDaemons/com.afterdarksys.darkd.plist <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.afterdarksys.darkd</string>
    <key>ProgramArguments</key>
    <array>
        <string>/usr/local/bin/afterdark-darkd</string>
        <string>--config</string>
        <string>/etc/afterdark/darkd.yaml</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>/var/log/afterdark/darkd.log</string>
    <key>StandardErrorPath</key>
    <string>/var/log/afterdark/darkd.error.log</string>
</dict>
</plist>
EOF

    launchctl load /Library/LaunchDaemons/com.afterdarksys.darkd.plist
}

# Main
main() {
    info "Installing AfterDark-DarkD..."

    setup_directories
    install_binaries
    install_config

    case "$OS" in
        macos)
            install_service_macos
            ;;
        *)
            install_service_linux
            ;;
    esac

    info ""
    info "Installation complete!"
    info ""
    info "Next steps:"
    info "  1. Edit /etc/afterdark/darkd.yaml"
    info "  2. Set DARKAPI_API_KEY environment variable"
    if [[ "$OS" == "macos" ]]; then
        info "  3. Start: sudo launchctl start com.afterdarksys.darkd"
    else
        info "  3. Start: sudo systemctl start afterdark-darkd"
    fi
    info "  4. Check status: afterdark-darkdadm status"
}

main "$@"
