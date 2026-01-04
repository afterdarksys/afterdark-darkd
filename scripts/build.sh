#!/bin/bash
#
# Build script for AfterDark-DarkD
# After Dark Systems, LLC
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

cd "$PROJECT_ROOT"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

info() { echo -e "${GREEN}[INFO]${NC} $1"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1"; exit 1; }
section() { echo -e "\n${BLUE}=== $1 ===${NC}"; }

# Version info
VERSION="${VERSION:-$(cat VERSION 2>/dev/null || echo "0.1.0")}"
COMMIT="${COMMIT:-$(git rev-parse --short HEAD 2>/dev/null || echo "unknown")}"
BUILD_TIME="${BUILD_TIME:-$(date -u '+%Y-%m-%d_%H:%M:%S')}"

# Build flags
LDFLAGS="-X main.Version=${VERSION} -X main.Commit=${COMMIT} -X main.BuildTime=${BUILD_TIME}"

# Platforms
PLATFORMS=(
    "darwin/amd64"
    "darwin/arm64"
    "linux/amd64"
    "linux/arm64"
    "windows/amd64"
)

# Core binaries
BINARIES=(
    "afterdark-darkd:cmd/afterdark-darkd"
    "afterdark-darkdadm:cmd/afterdark-darkdadm"
    "darkapi:cmd/darkapi"
    "darkd-config:cmd/darkd-config"
)

# Firewall plugins (platform-specific)
FIREWALL_PLUGINS=(
    "firewall-linux:plugins/firewall-linux:linux"
    "firewall-macos:plugins/firewall-macos:darwin"
    "firewall-windows:plugins/firewall-windows:windows"
)

# Example plugins
EXAMPLE_PLUGINS=(
    "hello-service:examples/plugins/hello-service"
    "threatfeed-datasource:examples/plugins/threatfeed-datasource"
)

build_proto() {
    section "Generating Protocol Buffers"

    if ! command -v protoc &> /dev/null; then
        warn "protoc not found, skipping proto generation"
        return 0
    fi

    # Check for Go plugins
    if ! command -v protoc-gen-go &> /dev/null; then
        info "Installing protoc-gen-go..."
        go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
    fi
    if ! command -v protoc-gen-go-grpc &> /dev/null; then
        info "Installing protoc-gen-go-grpc..."
        go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest
    fi

    mkdir -p api/proto/plugin

    for proto in api/proto/plugin/*.proto; do
        info "  Generating from $proto..."
        protoc --go_out=. --go_opt=paths=source_relative \
               --go-grpc_out=. --go-grpc_opt=paths=source_relative \
               "$proto" 2>/dev/null || warn "Failed to generate $proto (may need dependencies)"
    done

    info "Proto generation complete!"
}

build_local() {
    section "Building for Local Platform ($(go env GOOS)/$(go env GOARCH))"

    # Build core binaries
    for bin in "${BINARIES[@]}"; do
        name="${bin%%:*}"
        path="${bin##*:}"

        # Skip GUI if Fyne not available and building config tool
        if [[ "$name" == "darkd-config" ]]; then
            if ! go list fyne.io/fyne/v2 &>/dev/null 2>&1; then
                warn "Skipping $name (Fyne not installed - run: go get fyne.io/fyne/v2)"
                continue
            fi
        fi

        info "  Building $name..."
        go build -ldflags "$LDFLAGS" -o "$name" "./$path" || warn "Failed to build $name"
    done

    # Build firewall plugin for current platform
    current_os="$(go env GOOS)"
    for plugin in "${FIREWALL_PLUGINS[@]}"; do
        name="${plugin%%:*}"
        path="$(echo "$plugin" | cut -d: -f2)"
        target_os="$(echo "$plugin" | cut -d: -f3)"

        if [[ "$target_os" == "$current_os" ]]; then
            info "  Building plugin $name..."
            go build -ldflags "$LDFLAGS" -o "$name" "./$path" || warn "Failed to build $name"
        fi
    done

    info "Local build complete!"
}

build_all() {
    section "Building for All Platforms"

    mkdir -p dist

    for platform in "${PLATFORMS[@]}"; do
        os="${platform%/*}"
        arch="${platform#*/}"

        info "Building for $os/$arch..."

        # Build core binaries (skip GUI for cross-compile)
        for bin in "${BINARIES[@]}"; do
            name="${bin%%:*}"
            path="${bin##*:}"

            # Skip GUI for cross-compilation (requires CGO)
            if [[ "$name" == "darkd-config" ]]; then
                continue
            fi

            output="dist/${name}-${os}-${arch}"
            [[ "$os" == "windows" ]] && output="${output}.exe"

            GOOS="$os" GOARCH="$arch" go build -ldflags "$LDFLAGS" -o "$output" "./$path" || warn "Failed: $name for $os/$arch"
        done

        # Build firewall plugins for matching platforms
        for plugin in "${FIREWALL_PLUGINS[@]}"; do
            name="${plugin%%:*}"
            path="$(echo "$plugin" | cut -d: -f2)"
            target_os="$(echo "$plugin" | cut -d: -f3)"

            if [[ "$target_os" == "$os" ]]; then
                output="dist/${name}-${arch}"
                [[ "$os" == "windows" ]] && output="${output}.exe"

                info "  Building plugin $name..."
                GOOS="$os" GOARCH="$arch" go build -ldflags "$LDFLAGS" -o "$output" "./$path" || warn "Failed: $name"
            fi
        done
    done

    info "Cross-platform build complete!"
    ls -la dist/
}

build_plugins() {
    section "Building All Plugins"

    mkdir -p dist/plugins

    # Build firewall plugins
    info "Building firewall plugins..."
    for plugin in "${FIREWALL_PLUGINS[@]}"; do
        name="${plugin%%:*}"
        path="$(echo "$plugin" | cut -d: -f2)"
        target_os="$(echo "$plugin" | cut -d: -f3)"

        for arch in amd64 arm64; do
            output="dist/plugins/${name}-${arch}"
            [[ "$target_os" == "windows" ]] && output="${output}.exe"

            info "  Building $name ($target_os/$arch)..."
            GOOS="$target_os" GOARCH="$arch" go build -ldflags "$LDFLAGS" -o "$output" "./$path" 2>/dev/null || warn "Failed: $name for $arch"
        done
    done

    # Build example plugins
    info "Building example plugins..."
    for plugin in "${EXAMPLE_PLUGINS[@]}"; do
        name="${plugin%%:*}"
        path="${plugin##*:}"

        info "  Building $name..."
        go build -ldflags "$LDFLAGS" -o "dist/plugins/$name" "./$path" || warn "Failed: $name"
    done

    info "Plugin build complete!"
    ls -la dist/plugins/
}

build_gui() {
    section "Building GUI Application"

    # Check for Fyne
    if ! go list fyne.io/fyne/v2 &>/dev/null 2>&1; then
        info "Installing Fyne..."
        go get fyne.io/fyne/v2
    fi

    mkdir -p dist

    # GUI requires CGO, build for current platform only
    current_os="$(go env GOOS)"
    current_arch="$(go env GOARCH)"

    output="dist/darkd-config-${current_os}-${current_arch}"
    [[ "$current_os" == "windows" ]] && output="${output}.exe"

    info "Building darkd-config for $current_os/$current_arch..."
    CGO_ENABLED=1 go build -ldflags "$LDFLAGS" -o "$output" ./cmd/darkd-config

    # Create app bundle for macOS
    if [[ "$current_os" == "darwin" ]] && command -v fyne &>/dev/null; then
        info "Creating macOS app bundle..."
        fyne package -os darwin -name "AfterDark Config" -appID com.afterdark.config \
            -icon assets/icon.png ./cmd/darkd-config 2>/dev/null || warn "App bundle creation failed (install fyne CLI: go install fyne.io/fyne/v2/cmd/fyne@latest)"
    fi

    info "GUI build complete!"
}

build_docker() {
    section "Building Docker Image"
    docker build -t afterdark-darkd:${VERSION} -f deployments/docker/Dockerfile .
    docker tag afterdark-darkd:${VERSION} afterdark-darkd:latest
    info "Docker build complete!"
}

build_release() {
    section "Building Release (Full)"

    clean
    build_proto
    build_all
    build_plugins

    # Create release archives
    info "Creating release archives..."
    mkdir -p dist/release

    for platform in "${PLATFORMS[@]}"; do
        os="${platform%/*}"
        arch="${platform#*/}"

        archive_name="afterdark-darkd-${VERSION}-${os}-${arch}"

        if [[ "$os" == "windows" ]]; then
            # Create zip for Windows
            (cd dist && zip -q "${archive_name}.zip" \
                afterdark-darkd-${os}-${arch}.exe \
                afterdark-darkdadm-${os}-${arch}.exe \
                darkapi-${os}-${arch}.exe \
                firewall-windows-${arch}.exe 2>/dev/null) || true
            mv "dist/${archive_name}.zip" dist/release/ 2>/dev/null || true
        else
            # Create tarball for Unix
            (cd dist && tar -czf "${archive_name}.tar.gz" \
                afterdark-darkd-${os}-${arch} \
                afterdark-darkdadm-${os}-${arch} \
                darkapi-${os}-${arch} \
                firewall-*-${arch} 2>/dev/null) || true
            mv "dist/${archive_name}.tar.gz" dist/release/ 2>/dev/null || true
        fi
    done

    info "Release build complete!"
    ls -la dist/release/
}

clean() {
    section "Cleaning Build Artifacts"
    rm -f afterdark-darkd afterdark-darkdadm darkapi darkd-config
    rm -f firewall-linux firewall-macos firewall-windows
    rm -f hello-service threatfeed-datasource
    rm -rf dist/
    rm -rf *.app  # macOS app bundles
    info "Clean complete!"
}

deps() {
    section "Installing Dependencies"

    info "Running go mod tidy..."
    go mod tidy

    info "Installing build tools..."
    go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
    go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest

    # Optional: Fyne for GUI
    if [[ "${INSTALL_FYNE:-}" == "1" ]]; then
        info "Installing Fyne..."
        go get fyne.io/fyne/v2
        go install fyne.io/fyne/v2/cmd/fyne@latest
    fi

    info "Dependencies installed!"
}

usage() {
    cat <<EOF
Usage: $0 [command]

Commands:
    local       Build for local platform (default)
    all         Build for all platforms (cross-compile)
    plugins     Build all plugins only
    gui         Build GUI config tool (current platform)
    proto       Generate protocol buffer code
    docker      Build Docker image
    release     Full release build with archives
    deps        Install build dependencies
    clean       Remove build artifacts
    help        Show this help

Environment variables:
    VERSION       Version string (default: from VERSION file or 0.1.0)
    COMMIT        Git commit hash (default: from git)
    BUILD_TIME    Build timestamp (default: current time)
    INSTALL_FYNE  Set to 1 to install Fyne with deps command

Examples:
    $0                          # Build for local platform
    $0 all                      # Build for all platforms
    $0 plugins                  # Build just plugins
    $0 gui                      # Build GUI tool
    $0 release                  # Full release build
    VERSION=1.0.0 $0 release    # Release with custom version
    INSTALL_FYNE=1 $0 deps      # Install deps including Fyne
EOF
}

case "${1:-local}" in
    local)
        build_local
        ;;
    all)
        build_all
        ;;
    plugins)
        build_plugins
        ;;
    gui)
        build_gui
        ;;
    proto)
        build_proto
        ;;
    docker)
        build_docker
        ;;
    release)
        build_release
        ;;
    deps)
        deps
        ;;
    clean)
        clean
        ;;
    help|--help|-h)
        usage
        ;;
    *)
        error "Unknown command: $1"
        ;;
esac
