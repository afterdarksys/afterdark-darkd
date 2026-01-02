# Go parameters
GOCMD=go
GOBUILD=$(GOCMD) build
GOCLEAN=$(GOCMD) clean
GOTEST=$(GOCMD) test
GOGET=$(GOCMD) get
GOMOD=$(GOCMD) mod

# Binary names
DAEMON_BINARY=afterdark-darkd
ADMIN_BINARY=afterdark-darkdadm
CLI_BINARY=darkapi

# Version information
VERSION ?= 0.1.0
COMMIT ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
BUILD_TIME ?= $(shell date -u '+%Y-%m-%d_%H:%M:%S')

# Build flags
LDFLAGS=-ldflags "-X main.Version=$(VERSION) -X main.Commit=$(COMMIT) -X main.BuildTime=$(BUILD_TIME)"

# Platforms
PLATFORMS=darwin/amd64 darwin/arm64 linux/amd64 linux/arm64 windows/amd64

.PHONY: all build clean test coverage deps help

all: deps test build

## build: Build all binaries
build: build-daemon build-admin build-cli

## build-daemon: Build daemon binary
build-daemon:
	$(GOBUILD) $(LDFLAGS) -o $(DAEMON_BINARY) ./cmd/afterdark-darkd

## build-admin: Build admin CLI binary
build-admin:
	$(GOBUILD) $(LDFLAGS) -o $(ADMIN_BINARY) ./cmd/afterdark-darkdadm

## build-cli: Build user CLI binary
build-cli:
	$(GOBUILD) $(LDFLAGS) -o $(CLI_BINARY) ./cmd/darkapi

## build-all: Build for all platforms
build-all:
	@mkdir -p dist
	@for platform in $(PLATFORMS); do \
		GOOS=$${platform%/*} GOARCH=$${platform#*/} \
		$(GOBUILD) $(LDFLAGS) -o dist/$(DAEMON_BINARY)-$${platform%/*}-$${platform#*/}$$([ "$${platform%/*}" = "windows" ] && echo ".exe") ./cmd/afterdark-darkd; \
		GOOS=$${platform%/*} GOARCH=$${platform#*/} \
		$(GOBUILD) $(LDFLAGS) -o dist/$(ADMIN_BINARY)-$${platform%/*}-$${platform#*/}$$([ "$${platform%/*}" = "windows" ] && echo ".exe") ./cmd/afterdark-darkdadm; \
		GOOS=$${platform%/*} GOARCH=$${platform#*/} \
		$(GOBUILD) $(LDFLAGS) -o dist/$(CLI_BINARY)-$${platform%/*}-$${platform#*/}$$([ "$${platform%/*}" = "windows" ] && echo ".exe") ./cmd/darkapi; \
		echo "Built for $${platform}"; \
	done

## test: Run unit tests
test:
	$(GOTEST) -v -race -coverprofile=coverage.out ./...

## coverage: Generate coverage report
coverage: test
	$(GOCMD) tool cover -html=coverage.out -o coverage.html

## integration: Run integration tests
integration:
	$(GOTEST) -v -race -tags=integration ./test/integration/...

## bench: Run benchmarks
bench:
	$(GOTEST) -bench=. -benchmem ./...

## clean: Clean build artifacts
clean:
	$(GOCLEAN)
	rm -f $(DAEMON_BINARY) $(ADMIN_BINARY) $(CLI_BINARY)
	rm -f coverage.out coverage.html
	rm -rf dist/

## deps: Download dependencies
deps:
	$(GOMOD) download
	$(GOMOD) tidy

## fmt: Format code
fmt:
	$(GOCMD) fmt ./...

## lint: Run linters
lint:
	golangci-lint run ./...

## proto: Generate protobuf code
proto:
	protoc --go_out=. --go_opt=paths=source_relative \
		--go-grpc_out=. --go-grpc_opt=paths=source_relative \
		api/proto/*.proto

## install: Install binaries
install: build
	install -m 755 $(DAEMON_BINARY) /usr/local/bin/
	install -m 755 $(ADMIN_BINARY) /usr/local/bin/
	install -m 755 $(CLI_BINARY) /usr/local/bin/

## run: Run daemon in development mode
run: build-daemon
	./$(DAEMON_BINARY) --config configs/darkd.yaml.example --log-level debug

## help: Show this help
help:
	@echo "Usage: make [target]"
	@echo ""
	@echo "Available targets:"
	@sed -n 's/^##//p' $(MAKEFILE_LIST) | column -t -s ':' | sed -e 's/^/ /'
