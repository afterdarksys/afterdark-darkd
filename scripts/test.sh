#!/bin/bash
#
# Test script for AfterDark-DarkD
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
header() { echo -e "\n${BLUE}=== $1 ===${NC}\n"; }

# Coverage threshold
COVERAGE_THRESHOLD=${COVERAGE_THRESHOLD:-60}

run_unit_tests() {
    header "Running Unit Tests"

    go test -v -race -coverprofile=coverage.out ./...

    # Check coverage
    COVERAGE=$(go tool cover -func=coverage.out | grep total | awk '{print $3}' | sed 's/%//')
    info "Total coverage: ${COVERAGE}%"

    if (( $(echo "$COVERAGE < $COVERAGE_THRESHOLD" | bc -l) )); then
        warn "Coverage ${COVERAGE}% is below threshold ${COVERAGE_THRESHOLD}%"
    else
        info "Coverage meets threshold!"
    fi
}

run_integration_tests() {
    header "Running Integration Tests"

    go test -v -race -tags=integration ./test/integration/...
}

run_e2e_tests() {
    header "Running E2E Tests"

    # Build binaries first
    make build

    go test -v -tags=e2e ./test/e2e/...
}

run_benchmarks() {
    header "Running Benchmarks"

    go test -bench=. -benchmem -run=^$ ./...
}

run_lint() {
    header "Running Linter"

    if command -v golangci-lint &> /dev/null; then
        golangci-lint run ./...
    else
        warn "golangci-lint not installed, running go vet instead"
        go vet ./...
    fi
}

run_security_scan() {
    header "Running Security Scan"

    if command -v gosec &> /dev/null; then
        gosec -quiet ./...
    else
        warn "gosec not installed, skipping security scan"
        info "Install with: go install github.com/securego/gosec/v2/cmd/gosec@latest"
    fi
}

generate_coverage_report() {
    header "Generating Coverage Report"

    if [[ -f coverage.out ]]; then
        go tool cover -html=coverage.out -o coverage.html
        info "Coverage report generated: coverage.html"
    else
        warn "No coverage data found, run unit tests first"
    fi
}

run_all() {
    run_lint
    run_unit_tests
    run_security_scan
    generate_coverage_report

    header "All Tests Complete"
    info "Results:"
    info "  - Coverage report: coverage.html"
    info "  - Coverage data: coverage.out"
}

usage() {
    cat <<EOF
Usage: $0 [command]

Commands:
    unit            Run unit tests with coverage
    integration     Run integration tests
    e2e             Run end-to-end tests
    bench           Run benchmarks
    lint            Run linter
    security        Run security scan
    coverage        Generate HTML coverage report
    all             Run all tests (default)
    help            Show this help

Environment variables:
    COVERAGE_THRESHOLD  Minimum coverage percentage (default: 60)

Examples:
    $0                          # Run all tests
    $0 unit                     # Run only unit tests
    COVERAGE_THRESHOLD=80 $0    # Run with 80% coverage threshold
EOF
}

case "${1:-all}" in
    unit)
        run_unit_tests
        ;;
    integration)
        run_integration_tests
        ;;
    e2e)
        run_e2e_tests
        ;;
    bench)
        run_benchmarks
        ;;
    lint)
        run_lint
        ;;
    security)
        run_security_scan
        ;;
    coverage)
        generate_coverage_report
        ;;
    all)
        run_all
        ;;
    help|--help|-h)
        usage
        ;;
    *)
        error "Unknown command: $1"
        ;;
esac
