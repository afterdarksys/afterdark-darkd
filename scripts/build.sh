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
NC='\033[0m'

info() { echo -e "${GREEN}[INFO]${NC} $1"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1"; exit 1; }

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

# Binaries
BINARIES=(
    "afterdark-darkd:cmd/afterdark-darkd"
    "afterdark-darkdadm:cmd/afterdark-darkdadm"
    "darkapi:cmd/darkapi"
)

build_local() {
    info "Building for local platform..."

    for bin in "${BINARIES[@]}"; do
        name="${bin%%:*}"
        path="${bin##*:}"
        info "  Building $name..."
        go build -ldflags "$LDFLAGS" -o "$name" "./$path"
    done

    info "Local build complete!"
}

build_all() {
    info "Building for all platforms..."

    mkdir -p dist

    for platform in "${PLATFORMS[@]}"; do
        os="${platform%/*}"
        arch="${platform#*/}"

        info "Building for $os/$arch..."

        for bin in "${BINARIES[@]}"; do
            name="${bin%%:*}"
            path="${bin##*:}"

            output="dist/${name}-${os}-${arch}"
            [[ "$os" == "windows" ]] && output="${output}.exe"

            GOOS="$os" GOARCH="$arch" go build -ldflags "$LDFLAGS" -o "$output" "./$path"
        done
    done

    info "Cross-platform build complete!"
    ls -la dist/
}

build_docker() {
    info "Building Docker image..."
    docker build -t afterdark-darkd:${VERSION} -f deployments/docker/Dockerfile .
    docker tag afterdark-darkd:${VERSION} afterdark-darkd:latest
    info "Docker build complete!"
}

clean() {
    info "Cleaning build artifacts..."
    rm -f afterdark-darkd afterdark-darkdadm darkapi
    rm -rf dist/
    info "Clean complete!"
}

usage() {
    cat <<EOF
Usage: $0 [command]

Commands:
    local       Build for local platform (default)
    all         Build for all platforms
    docker      Build Docker image
    clean       Remove build artifacts
    help        Show this help

Environment variables:
    VERSION     Version string (default: from VERSION file or 0.1.0)
    COMMIT      Git commit hash (default: from git)
    BUILD_TIME  Build timestamp (default: current time)

Examples:
    $0                      # Build for local platform
    $0 all                  # Build for all platforms
    VERSION=1.0.0 $0 all    # Build with custom version
EOF
}

case "${1:-local}" in
    local)
        build_local
        ;;
    all)
        build_all
        ;;
    docker)
        build_docker
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
