# AfterDark macOS Security Plugin
# Build and install utilities

PLUGIN_NAME := osx-security
VERSION := 1.0.0
BUILD_DIR := ../../build/plugins
INSTALL_DIR := /var/lib/afterdark-darkd/plugins

# Build flags
LDFLAGS := -ldflags "-s -w -X main.PluginVersion=$(VERSION)"
BUILD_FLAGS := -trimpath

# Go settings
GO := go
GOFMT := gofmt
GOTEST := go test
GOVET := go vet

# Detect OS and architecture
GOOS := $(shell go env GOOS)
GOARCH := $(shell go env GOARCH)

.PHONY: all build build-all clean install uninstall test fmt vet lint help

all: build

## Build the plugin for current platform
build:
	@echo "Building $(PLUGIN_NAME) for $(GOOS)/$(GOARCH)..."
	@mkdir -p $(BUILD_DIR)
	$(GO) build $(BUILD_FLAGS) $(LDFLAGS) -o $(BUILD_DIR)/$(PLUGIN_NAME) .
	@echo "Built: $(BUILD_DIR)/$(PLUGIN_NAME)"

## Build for all supported platforms
build-all: build-darwin-amd64 build-darwin-arm64

build-darwin-amd64:
	@echo "Building for darwin/amd64..."
	@mkdir -p $(BUILD_DIR)
	GOOS=darwin GOARCH=amd64 $(GO) build $(BUILD_FLAGS) $(LDFLAGS) \
		-o $(BUILD_DIR)/$(PLUGIN_NAME)-darwin-amd64 .

build-darwin-arm64:
	@echo "Building for darwin/arm64..."
	@mkdir -p $(BUILD_DIR)
	GOOS=darwin GOARCH=arm64 $(GO) build $(BUILD_FLAGS) $(LDFLAGS) \
		-o $(BUILD_DIR)/$(PLUGIN_NAME)-darwin-arm64 .

## Build universal macOS binary
build-universal: build-darwin-amd64 build-darwin-arm64
	@echo "Creating universal binary..."
	lipo -create -output $(BUILD_DIR)/$(PLUGIN_NAME)-darwin-universal \
		$(BUILD_DIR)/$(PLUGIN_NAME)-darwin-amd64 \
		$(BUILD_DIR)/$(PLUGIN_NAME)-darwin-arm64
	@echo "Built: $(BUILD_DIR)/$(PLUGIN_NAME)-darwin-universal"

## Install the plugin (requires root for system install)
install: build
	@echo "Installing $(PLUGIN_NAME) to $(INSTALL_DIR)..."
	@sudo mkdir -p $(INSTALL_DIR)
	@sudo cp $(BUILD_DIR)/$(PLUGIN_NAME) $(INSTALL_DIR)/
	@sudo chmod 755 $(INSTALL_DIR)/$(PLUGIN_NAME)
	@echo "Installed: $(INSTALL_DIR)/$(PLUGIN_NAME)"

## Install to user-local directory (no root required)
install-local: build
	@echo "Installing $(PLUGIN_NAME) to ~/.afterdark/plugins..."
	@mkdir -p $(HOME)/.afterdark/plugins
	@cp $(BUILD_DIR)/$(PLUGIN_NAME) $(HOME)/.afterdark/plugins/
	@chmod 755 $(HOME)/.afterdark/plugins/$(PLUGIN_NAME)
	@echo "Installed: $(HOME)/.afterdark/plugins/$(PLUGIN_NAME)"

## Uninstall the plugin
uninstall:
	@echo "Removing $(PLUGIN_NAME) from $(INSTALL_DIR)..."
	@sudo rm -f $(INSTALL_DIR)/$(PLUGIN_NAME)
	@echo "Removed: $(INSTALL_DIR)/$(PLUGIN_NAME)"

## Run tests
test:
	@echo "Running tests..."
	$(GOTEST) -v ./...

## Run tests with coverage
test-coverage:
	@echo "Running tests with coverage..."
	$(GOTEST) -v -coverprofile=coverage.out ./...
	$(GO) tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report: coverage.html"

## Format code
fmt:
	@echo "Formatting code..."
	$(GOFMT) -s -w .

## Run go vet
vet:
	@echo "Running go vet..."
	$(GOVET) ./...

## Run all linters
lint: fmt vet
	@echo "Running staticcheck (if installed)..."
	@which staticcheck > /dev/null && staticcheck ./... || echo "staticcheck not installed, skipping"

## Clean build artifacts
clean:
	@echo "Cleaning build artifacts..."
	@rm -rf $(BUILD_DIR)/$(PLUGIN_NAME)*
	@rm -f coverage.out coverage.html
	@echo "Clean complete"

## Show module dependencies
deps:
	$(GO) mod download
	$(GO) mod tidy

## Update dependencies
deps-update:
	$(GO) get -u ./...
	$(GO) mod tidy

## Quick standalone test
run-test: build
	@echo "Running quick standalone test..."
	$(BUILD_DIR)/$(PLUGIN_NAME) status

## Run DS audit
run-ds-audit: build
	@echo "Running Directory Services audit..."
	$(BUILD_DIR)/$(PLUGIN_NAME) ds_audit

## Run keychain analysis
run-keychain: build
	@echo "Running keychain analysis..."
	$(BUILD_DIR)/$(PLUGIN_NAME) keychain_analyze

## Run full audit
run-full-audit: build
	@echo "Running full security audit..."
	$(BUILD_DIR)/$(PLUGIN_NAME) full_audit

## Show version
version:
	@echo "$(PLUGIN_NAME) version $(VERSION)"

## Show help
help:
	@echo "AfterDark macOS Security Plugin"
	@echo ""
	@echo "Usage: make [target]"
	@echo ""
	@echo "Build targets:"
	@echo "  build           Build for current platform"
	@echo "  build-all       Build for all macOS platforms"
	@echo "  build-universal Build universal macOS binary"
	@echo "  clean           Clean build artifacts"
	@echo ""
	@echo "Install targets:"
	@echo "  install         Install to system plugin directory (requires root)"
	@echo "  install-local   Install to ~/.afterdark/plugins"
	@echo "  uninstall       Remove from system plugin directory"
	@echo ""
	@echo "Development targets:"
	@echo "  test            Run tests"
	@echo "  test-coverage   Run tests with coverage report"
	@echo "  fmt             Format code"
	@echo "  vet             Run go vet"
	@echo "  lint            Run all linters"
	@echo "  deps            Download dependencies"
	@echo "  deps-update     Update dependencies"
	@echo ""
	@echo "Run targets:"
	@echo "  run-test        Quick standalone test"
	@echo "  run-ds-audit    Run Directory Services audit"
	@echo "  run-keychain    Run keychain analysis"
	@echo "  run-full-audit  Run full security audit"
	@echo ""
	@echo "Other:"
	@echo "  version         Show version"
	@echo "  help            Show this help"
