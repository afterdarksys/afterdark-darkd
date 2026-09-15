# Core daemon and CLI builds. GUI and signed native sensors are separate variants.
GO ?= go
BUILD_DIR ?= dist
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT := $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
LDFLAGS = -s -w -X main.Version=$(VERSION) -X main.Commit=$(COMMIT)
CORE = ./internal/... ./pkg/... ./cmd/afterdark-darkd ./cmd/afterdark-darkdadm ./cmd/darkapi

.PHONY: all build build-all test test-race vet native-es clean build-linux build-macos-arm64 build-macos-amd64 build-windows
all: build
build:
	@mkdir -p $(BUILD_DIR)
	$(GO) build -trimpath -ldflags '$(LDFLAGS)' -o $(BUILD_DIR)/ ./cmd/afterdark-darkd ./cmd/afterdark-darkdadm ./cmd/darkapi
build-all:
	GO=$(GO) BUILD_DIR=$(BUILD_DIR) VERSION=$(VERSION) COMMIT=$(COMMIT) bash scripts/build-platforms.sh
test:
	$(GO) test $(CORE)
test-race:
	$(GO) test -race $(CORE)
vet:
	$(GO) vet $(CORE)
# Requires a native macOS SDK; runtime also requires Apple authorization/signing.
native-es:
	@mkdir -p $(BUILD_DIR)
	CGO_ENABLED=1 $(GO) build -trimpath -tags esf -ldflags '$(LDFLAGS)' -o $(BUILD_DIR)/afterdark-darkd-es ./cmd/afterdark-darkd
build-linux:
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 $(GO) build -o $(BUILD_DIR)/afterdark-darkd-linux-amd64 ./cmd/afterdark-darkd
build-macos-arm64:
	GOOS=darwin GOARCH=arm64 CGO_ENABLED=0 $(GO) build -o $(BUILD_DIR)/afterdark-darkd-darwin-arm64 ./cmd/afterdark-darkd
build-macos-amd64:
	GOOS=darwin GOARCH=amd64 CGO_ENABLED=0 $(GO) build -o $(BUILD_DIR)/afterdark-darkd-darwin-amd64 ./cmd/afterdark-darkd
build-windows:
	GOOS=windows GOARCH=amd64 CGO_ENABLED=0 $(GO) build -o $(BUILD_DIR)/afterdark-darkd-windows-amd64.exe ./cmd/afterdark-darkd
clean:
	rm -rf $(BUILD_DIR)
