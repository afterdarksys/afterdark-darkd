# AfterDark Security Suite Makefile

BINARY_NAME=afterdark-darkd
BUILD_DIR=bin
LDFLAGS=-ldflags "-s -w -X main.Version=$(VERSION) -X main.Commit=$(COMMIT)"

VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
COMMIT := $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")

.PHONY: all clean build-linux build-macos-arm64 build-macos-amd64 build-windows

all: clean build-linux build-macos-arm64 build-macos-amd64 build-windows

clean:
	rm -rf $(BUILD_DIR)

build-linux:
	@echo "Building for Linux (with eBPF support)..."
	GOOS=linux GOARCH=amd64 go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-linux-amd64 ./cmd/afterdark-darkd
	@echo "Done."

build-macos-arm64:
	@echo "Building for macOS (Apple Silicon)..."
	GOOS=darwin GOARCH=arm64 CGO_ENABLED=1 go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-darwin-arm64 ./cmd/afterdark-darkd
	@echo "Done."

build-macos-amd64:
	@echo "Building for macOS (Intel)..."
	GOOS=darwin GOARCH=amd64 CGO_ENABLED=1 go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-darwin-amd64 ./cmd/afterdark-darkd
	@echo "Done."

build-windows:
	@echo "Building for Windows..."
	GOOS=windows GOARCH=amd64 go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-windows-amd64.exe ./cmd/afterdark-darkd
	@echo "Done."

# Generate eBPF artifacts
generate-ebpf:
	@echo "Generating eBPF artifacts..."
	go generate ./internal/service/ebpf/...

# Signing (macOS)
# Usage: make sign-macos IDENTITY="Developer ID Application: Your Name (TEAMID)"
sign-macos:
	@echo "Signing macOS binary..."
	codesign --sign "$(IDENTITY)" --entitlements ./internal/platform/darwin/esf/entitlements.plist --options runtime --timestamp --force $(BUILD_DIR)/$(BINARY_NAME)-darwin-amd64
	codesign --sign "$(IDENTITY)" --entitlements ./internal/platform/darwin/esf/entitlements.plist --options runtime --timestamp --force $(BUILD_DIR)/$(BINARY_NAME)-darwin-arm64
	@echo "Verification:"
	codesign --verify --deep --strict --verbose=2 $(BUILD_DIR)/$(BINARY_NAME)-darwin-amd64

