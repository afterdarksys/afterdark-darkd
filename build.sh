#!/bin/bash
# AfterDark Build Helper
# Usage: ./build.sh [command] [arch]
# Commands: build, rebuild, clean
# Arch: osxi (macOS Intel), osxa (macOS ARM), linux, linuxa, windows, windowsa

set -e

VERSION=$(git describe --tags --always --dirty 2>/dev/null || echo "dev")
COMMIT=$(git rev-parse --short HEAD 2>/dev/null || echo "unknown")
BUILD_TIME=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

LDFLAGS="-s -w -X main.Version=${VERSION} -X main.Commit=${COMMIT} -X main.BuildTime=${BUILD_TIME}"

BINARIES=(
    "cmd/afterdark-darkd:afterdark_darkd"
    "cmd/afterdark-darkdadm:darkdadm"
    "cmd/darkapi:darkapi"
)

BUILD_DIR="build"

# Get platform suffix for output filename
get_platform_suffix() {
    local goos=$1
    local goarch=$2

    case "${goos}:${goarch}" in
        darwin:amd64)  echo ".osxi" ;;
        darwin:arm64)  echo ".osxa" ;;
        linux:amd64)   echo ".x86" ;;
        linux:arm64)   echo ".linuxa" ;;
        windows:amd64) echo ".win64.exe" ;;
        windows:arm64) echo ".wina.exe" ;;
        *)             echo "" ;;
    esac
}

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

print_status() {
    echo -e "${CYAN}==>${NC} $1"
}

print_success() {
    echo -e "${GREEN}==>${NC} $1"
}

print_error() {
    echo -e "${RED}Error:${NC} $1"
}

# Resolve architecture
resolve_arch() {
    local arch=$1
    case $arch in
        osxi|macos-intel|darwin-amd64)
            echo "darwin:amd64"
            ;;
        osxa|macos-arm|darwin-arm64|macos)
            echo "darwin:arm64"
            ;;
        linux|linux-amd64)
            echo "linux:amd64"
            ;;
        linuxa|linux-arm64)
            echo "linux:arm64"
            ;;
        windows|windows-amd64|win)
            echo "windows:amd64"
            ;;
        windowsa|windows-arm64|wina)
            echo "windows:arm64"
            ;;
        all)
            echo "all"
            ;;
        *)
            # Default to current platform
            echo "$(go env GOOS):$(go env GOARCH)"
            ;;
    esac
}

# Build for specific platform
build_platform() {
    local goos=$1
    local goarch=$2
    local platform_suffix=$(get_platform_suffix "$goos" "$goarch")

    mkdir -p "$BUILD_DIR"

    for binary in "${BINARIES[@]}"; do
        local src="${binary%%:*}"
        local name="${binary##*:}"
        local out="${BUILD_DIR}/${name}${platform_suffix}"

        print_status "Building ${name} for ${goos}/${goarch}..."
        CGO_ENABLED=0 GOOS=$goos GOARCH=$goarch go build -ldflags="${LDFLAGS}" -o "$out" "./${src}"
        print_success "Built: $out"
    done
}

# Build command
cmd_build() {
    local arch="${1:-}"
    local resolved=$(resolve_arch "$arch")

    if [ "$resolved" == "all" ]; then
        print_status "Building for all platforms..."
        build_platform darwin amd64
        build_platform darwin arm64
        build_platform linux amd64
        build_platform linux arm64
        build_platform windows amd64
        build_platform windows arm64
    else
        local goos="${resolved%%:*}"
        local goarch="${resolved##*:}"
        build_platform "$goos" "$goarch"
    fi

    print_success "Build complete!"
}

# Rebuild command (clean + build)
cmd_rebuild() {
    cmd_clean
    cmd_build "$1"
}

# Clean command
cmd_clean() {
    print_status "Cleaning build directory..."
    rm -rf "$BUILD_DIR"
    print_success "Clean complete!"
}

# Install command (build and install to /usr/local/bin)
cmd_install() {
    local arch="${1:-}"
    local resolved=$(resolve_arch "$arch")
    local goos="${resolved%%:*}"
    local goarch="${resolved##*:}"

    # Build first
    build_platform "$goos" "$goarch"

    local platform_suffix=$(get_platform_suffix "$goos" "$goarch")

    print_status "Installing to /usr/local/bin..."
    sudo cp "${BUILD_DIR}/afterdark_darkd${platform_suffix}" /usr/local/bin/afterdark-darkd
    sudo cp "${BUILD_DIR}/darkdadm${platform_suffix}" /usr/local/bin/darkdadm
    sudo cp "${BUILD_DIR}/darkapi${platform_suffix}" /usr/local/bin/darkapi
    print_success "Installed: afterdark-darkd, darkdadm, darkapi"
}

# Test command
cmd_test() {
    print_status "Running tests..."
    go test -v ./...
    print_success "Tests complete!"
}

# Help
show_help() {
    cat << EOF
AfterDark Build Helper

Usage: ./build.sh [command] [arch]

Commands:
  build [arch]     Build binaries (default: current platform)
  rebuild [arch]   Clean and rebuild
  clean            Remove build directory
  install [arch]   Build and install to /usr/local/bin
  test             Run tests

Architectures:
  osxi             macOS Intel   -> afterdark_darkd.osxi
  osxa             macOS ARM     -> afterdark_darkd.osxa
  linux            Linux Intel   -> afterdark_darkd.x86
  linuxa           Linux ARM     -> afterdark_darkd.linuxa
  windows          Windows Intel -> afterdark_darkd.win64.exe
  windowsa         Windows ARM   -> afterdark_darkd.wina.exe
  all              Build for all platforms

Output:
  build/afterdark_darkd.<platform>
  build/darkdadm.<platform>
  build/darkapi.<platform>

Examples:
  ./build.sh build              # Build for current platform
  ./build.sh build osxa         # Build for macOS ARM
  ./build.sh rebuild all        # Rebuild for all platforms
  ./build.sh install            # Build and install locally

EOF
}

# Main
case "${1:-build}" in
    build)
        cmd_build "$2"
        ;;
    rebuild)
        cmd_rebuild "$2"
        ;;
    clean)
        cmd_clean
        ;;
    install)
        cmd_install "$2"
        ;;
    test)
        cmd_test
        ;;
    help|--help|-h)
        show_help
        ;;
    *)
        print_error "Unknown command: $1"
        show_help
        exit 1
        ;;
esac
