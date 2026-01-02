# AfterDark-DarkD Quick Start Guide

## Prerequisites

- Go 1.21 or later
- Git
- Make (for build automation)
- Platform-specific tools:
  - **macOS**: Xcode Command Line Tools
  - **Windows**: Visual Studio Build Tools or MinGW-w64
  - **Linux**: GCC, build-essential

## Initial Setup (TICKET-001)

### 1. Initialize Go Module

```bash
cd /Users/ryan/development/afterdark-darkd
go mod init github.com/afterdarksys/afterdark-darkd
```

### 2. Create Directory Structure

```bash
# Create all directories
mkdir -p cmd/{afterdark-darkd,afterdark-darkdadm,darkapi}
mkdir -p internal/{daemon,service,platform,api,storage,ipc,models}
mkdir -p internal/service/{patch,threat,baseline,network,report}
mkdir -p internal/platform/{macos,windows,linux}
mkdir -p internal/api/{afterdark,darkapi,dnsscience,veribits,integration}
mkdir -p internal/storage/{json,cache,audit}
mkdir -p pkg/{logging,metrics,retry,ratelimit,validator}
mkdir -p api/proto
mkdir -p configs/policies
mkdir -p scripts/{install,service,test}
mkdir -p scripts/service/{launchd,systemd,windows}
mkdir -p deployments/{docker,kubernetes,terraform}
mkdir -p test/{integration,e2e}
mkdir -p docs
mkdir -p .github/workflows
```

### 3. Create .gitignore

```bash
cat > .gitignore << 'EOF'
# Binaries
afterdark-darkd
afterdark-darkdadm
darkapi
*.exe
*.exe~
*.dll
*.so
*.dylib

# Test binary, built with `go test -c`
*.test

# Output of the go coverage tool
*.out
coverage.html

# Dependency directories
vendor/

# Go workspace file
go.work

# IDEs
.idea/
.vscode/
*.swp
*.swo
*~

# OS
.DS_Store
Thumbs.db

# Build artifacts
dist/
build/
*.pkg
*.deb
*.rpm
*.msi

# Runtime
*.pid
*.sock
*.log

# Local configuration
configs/*.yaml
!configs/*.yaml.example

# Data directories
/data/
/logs/

# Temporary files
tmp/
temp/

# Generated files
api/proto/*.pb.go
EOF
```

### 4. Initialize Git Repository

```bash
git init
git add .gitignore
git commit -m "Initial commit: project structure"
```

## Core Interface Files

### Create Platform Interface (TICKET-009)

File: `internal/platform/platform.go`

```go
package platform

import (
    "context"
    "time"
)

// Platform defines the interface for OS-specific operations
type Platform interface {
    // System Information
    GetOSInfo() (*OSInfo, error)
    GetHostname() (string, error)

    // Patch Management
    ListInstalledPatches(ctx context.Context) ([]Patch, error)
    ListAvailablePatches(ctx context.Context) ([]Patch, error)
    InstallPatch(ctx context.Context, patchID string) error

    // Application Inventory
    ListInstalledApplications(ctx context.Context) ([]Application, error)

    // Network Operations
    GetNetworkInterfaces() ([]NetworkInterface, error)
    GetPublicIP(ctx context.Context) (string, error)
    SetDNSServers(servers []string) error

    // Security Controls
    EnableFirewall() error
    DisableICMP(enabled bool) error
    BlockIPFragmentation(enabled bool) error
}

type OSInfo struct {
    Name         string
    Version      string
    Build        string
    Architecture string
    Kernel       string
}

type PatchSeverity int

const (
    SeverityUnknown PatchSeverity = iota
    SeverityLow
    SeverityModerate
    SeverityImportant
    SeverityCritical
    SeverityExploitActive
)

func (s PatchSeverity) String() string {
    switch s {
    case SeverityLow:
        return "low"
    case SeverityModerate:
        return "moderate"
    case SeverityImportant:
        return "important"
    case SeverityCritical:
        return "critical"
    case SeverityExploitActive:
        return "exploit-active"
    default:
        return "unknown"
    }
}

type PatchCategory int

const (
    CategoryUnknown PatchCategory = iota
    CategoryKernel
    CategoryNetwork
    CategorySoftware
    CategorySecurity
)

func (c PatchCategory) String() string {
    switch c {
    case CategoryKernel:
        return "kernel"
    case CategoryNetwork:
        return "network"
    case CategorySoftware:
        return "software"
    case CategorySecurity:
        return "security"
    default:
        return "unknown"
    }
}

type Patch struct {
    ID           string
    Name         string
    Description  string
    Severity     PatchSeverity
    Category     PatchCategory
    InstalledAt  *time.Time
    ReleasedAt   time.Time
    CVEs         []string
    KBArticle    string
    Size         int64
}

type Application struct {
    Name        string
    Version     string
    Vendor      string
    InstallDate time.Time
    InstallPath string
}

type NetworkInterface struct {
    Name       string
    MACAddress string
    IPAddress  string
    Status     string
}

// Factory returns the appropriate Platform implementation for the current OS
func Factory() (Platform, error) {
    // Implementation will detect OS and return appropriate platform
    return nil, nil
}
```

### Create Service Interface (TICKET-007)

File: `internal/service/service.go`

```go
package service

import (
    "context"
    "time"
)

// Service defines the interface all services must implement
type Service interface {
    // Name returns the service identifier
    Name() string

    // Start initializes and starts the service
    Start(ctx context.Context) error

    // Stop gracefully shuts down the service
    Stop(ctx context.Context) error

    // Health returns the current health status
    Health() HealthStatus

    // Configure updates service configuration
    Configure(config interface{}) error
}

type HealthStatus struct {
    Status    HealthState
    Message   string
    LastCheck time.Time
    Metrics   map[string]interface{}
}

type HealthState int

const (
    HealthUnknown HealthState = iota
    HealthHealthy
    HealthDegraded
    HealthUnhealthy
)

func (h HealthState) String() string {
    switch h {
    case HealthHealthy:
        return "healthy"
    case HealthDegraded:
        return "degraded"
    case HealthUnhealthy:
        return "unhealthy"
    default:
        return "unknown"
    }
}

// Registry manages service lifecycle
type Registry struct {
    services map[string]Service
}

func NewRegistry() *Registry {
    return &Registry{
        services: make(map[string]Service),
    }
}

func (r *Registry) Register(svc Service) {
    r.services[svc.Name()] = svc
}

func (r *Registry) StartAll(ctx context.Context) error {
    for name, svc := range r.services {
        if err := svc.Start(ctx); err != nil {
            return err
        }
    }
    return nil
}

func (r *Registry) StopAll(ctx context.Context) error {
    for name, svc := range r.services {
        if err := svc.Stop(ctx); err != nil {
            return err
        }
    }
    return nil
}

func (r *Registry) HealthCheck() map[string]HealthStatus {
    status := make(map[string]HealthStatus)
    for name, svc := range r.services {
        status[name] = svc.Health()
    }
    return status
}
```

### Create Configuration Model (TICKET-005)

File: `internal/models/config.go`

```go
package models

import "time"

// Config represents the daemon configuration
type Config struct {
    Daemon   DaemonConfig   `yaml:"daemon"`
    API      APIConfig      `yaml:"api"`
    Services ServicesConfig `yaml:"services"`
    Storage  StorageConfig  `yaml:"storage"`
    IPC      IPCConfig      `yaml:"ipc"`
}

type DaemonConfig struct {
    LogLevel string `yaml:"log_level"`
    DataDir  string `yaml:"data_dir"`
    PIDFile  string `yaml:"pid_file"`
}

type APIConfig struct {
    AfterDark  EndpointConfig `yaml:"afterdark"`
    DarkAPI    EndpointConfig `yaml:"darkapi"`
    DNSScience EndpointConfig `yaml:"dnsscience"`
    Veribits   EndpointConfig `yaml:"veribits"`
}

type EndpointConfig struct {
    URL     string        `yaml:"url"`
    APIKey  string        `yaml:"api_key"`
    Timeout time.Duration `yaml:"timeout"`
    Retry   RetryConfig   `yaml:"retry"`
}

type RetryConfig struct {
    MaxAttempts int           `yaml:"max_attempts"`
    InitialWait time.Duration `yaml:"initial_wait"`
    MaxWait     time.Duration `yaml:"max_wait"`
}

type ServicesConfig struct {
    PatchMonitor   PatchMonitorConfig   `yaml:"patch_monitor"`
    ThreatIntel    ThreatIntelConfig    `yaml:"threat_intel"`
    BaselineScanner BaselineScannerConfig `yaml:"baseline_scanner"`
    NetworkMonitor NetworkMonitorConfig `yaml:"network_monitor"`
}

type PatchMonitorConfig struct {
    Enabled            bool          `yaml:"enabled"`
    ScanInterval       time.Duration `yaml:"scan_interval"`
    AutoInstallWindows bool          `yaml:"auto_install_windows"`
    UrgencyTiers       UrgencyTiers  `yaml:"urgency_tiers"`
}

type UrgencyTiers struct {
    Critical        time.Duration `yaml:"critical"`
    KernelNetwork   time.Duration `yaml:"kernel_network"`
    Software        time.Duration `yaml:"software"`
    WindowsStandard time.Duration `yaml:"windows_standard"`
}

type ThreatIntelConfig struct {
    Enabled      bool          `yaml:"enabled"`
    SyncInterval time.Duration `yaml:"sync_interval"`
    CacheTTL     time.Duration `yaml:"cache_ttl"`
}

type BaselineScannerConfig struct {
    Enabled      bool          `yaml:"enabled"`
    ScanInterval time.Duration `yaml:"scan_interval"`
}

type NetworkMonitorConfig struct {
    Enabled             bool     `yaml:"enabled"`
    DNSServers          []string `yaml:"dns_servers"`
    AllowICMP           bool     `yaml:"allow_icmp"`
    BlockFragmentation  bool     `yaml:"block_fragmentation"`
}

type StorageConfig struct {
    Backend         string        `yaml:"backend"`
    Path            string        `yaml:"path"`
    BackupEnabled   bool          `yaml:"backup_enabled"`
    BackupRetention time.Duration `yaml:"backup_retention"`
}

type IPCConfig struct {
    SocketPath    string `yaml:"socket_path"`
    AuthEnabled   bool   `yaml:"auth_enabled"`
    AuthTokenFile string `yaml:"auth_token_file"`
}
```

### Create Example Configuration

File: `configs/darkd.yaml.example`

```yaml
daemon:
  log_level: info
  data_dir: /var/lib/afterdark
  pid_file: /var/run/afterdark/darkd.pid

api:
  afterdark:
    url: https://api.afterdarksys.com
    timeout: 30s
    retry:
      max_attempts: 3
      initial_wait: 1s
      max_wait: 30s

  darkapi:
    url: https://api.darkapi.io
    api_key: ${DARKAPI_API_KEY}
    timeout: 30s
    retry:
      max_attempts: 3
      initial_wait: 1s
      max_wait: 30s

  dnsscience:
    url: https://api.dnsscience.io
    timeout: 10s
    retry:
      max_attempts: 2
      initial_wait: 500ms
      max_wait: 5s

  veribits:
    url: https://api.veribits.com
    timeout: 20s

services:
  patch_monitor:
    enabled: true
    scan_interval: 1h
    auto_install_windows: true
    urgency_tiers:
      critical: 24h          # 1 day - MAJOR, CRITICAL, EXPLOIT ACTIVE
      kernel_network: 48h    # 2 days - Network or Kernel
      software: 72h          # 3 days - Software patches
      windows_standard: 168h # 7 days - Windows patches

  threat_intel:
    enabled: true
    sync_interval: 6h
    cache_ttl: 24h

  baseline_scanner:
    enabled: true
    scan_interval: 24h

  network_monitor:
    enabled: true
    dns_servers:
      - cache01.dnsscience.io
      - cache02.dnsscience.io
      - cache03.dnsscience.io
      - cache04.dnsscience.io
    allow_icmp: false
    block_fragmentation: true

storage:
  backend: json
  path: /var/lib/afterdark/data
  backup_enabled: true
  backup_retention: 720h # 30 days

ipc:
  socket_path: /var/run/afterdark/darkd.sock
  auth_enabled: true
  auth_token_file: /var/lib/afterdark/.auth_token
```

## Initial Dependencies

### 1. Add Core Dependencies

```bash
# Logging
go get -u go.uber.org/zap

# Configuration
go get -u gopkg.in/yaml.v3

# CLI framework
go get -u github.com/spf13/cobra
go get -u github.com/spf13/viper

# gRPC and protobuf
go get -u google.golang.org/grpc
go get -u google.golang.org/protobuf

# HTTP client
go get -u github.com/hashicorp/go-retryablehttp

# Testing
go get -u github.com/stretchr/testify

# Platform-specific (Windows)
go get -u golang.org/x/sys/windows

# Context and sync
go get -u golang.org/x/sync/errgroup
```

### 2. Create Makefile

File: `Makefile`

```makefile
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
COMMIT ?= $(shell git rev-parse --short HEAD)
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
    @for platform in $(PLATFORMS); do \
        GOOS=$${platform%/*} GOARCH=$${platform#*/} \
        $(GOBUILD) $(LDFLAGS) -o dist/$(DAEMON_BINARY)-$${platform%/*}-$${platform#*/} ./cmd/afterdark-darkd; \
        GOOS=$${platform%/*} GOARCH=$${platform#*/} \
        $(GOBUILD) $(LDFLAGS) -o dist/$(ADMIN_BINARY)-$${platform%/*}-$${platform#*/} ./cmd/afterdark-darkdadm; \
        GOOS=$${platform%/*} GOARCH=$${platform#*/} \
        $(GOBUILD) $(LDFLAGS) -o dist/$(CLI_BINARY)-$${platform%/*}-$${platform#*/} ./cmd/darkapi; \
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

## help: Show this help
help:
    @echo "Usage: make [target]"
    @echo ""
    @echo "Available targets:"
    @sed -n 's/^##//p' $(MAKEFILE_LIST) | column -t -s ':' | sed -e 's/^/ /'
```

## Build and Run

### 1. Build the Project

```bash
make deps
make build
```

### 2. Run the Daemon (Development Mode)

```bash
# Create necessary directories
sudo mkdir -p /var/lib/afterdark /var/run/afterdark /var/log/afterdark
sudo chown $(whoami) /var/lib/afterdark /var/run/afterdark /var/log/afterdark

# Copy example config
cp configs/darkd.yaml.example /var/lib/afterdark/darkd.yaml

# Set API key
export DARKAPI_API_KEY="your-api-key-here"

# Run daemon
./afterdark-darkd --config /var/lib/afterdark/darkd.yaml --log-level debug
```

### 3. Test CLI Tools

```bash
# Check daemon status
./afterdark-darkdadm status

# View patch information
./afterdark-darkdadm patches list

# User CLI
./darkapi status
```

## Development Workflow

### 1. Feature Branch

```bash
git checkout -b feature/TICKET-XXX-description
```

### 2. Write Tests First

```bash
# Create test file
touch internal/service/patch/scanner_test.go

# Write tests
# Implement feature
# Run tests
make test
```

### 3. Format and Lint

```bash
make fmt
make lint
```

### 4. Commit and Push

```bash
git add .
git commit -m "TICKET-XXX: Brief description"
git push origin feature/TICKET-XXX-description
```

### 5. Create Pull Request

Use GitHub UI to create PR from feature branch to main.

## Testing Strategy

### Unit Tests

```go
// Example: internal/service/patch/classifier_test.go
package patch_test

import (
    "testing"
    "time"

    "github.com/afterdarksys/afterdark-darkd/internal/service/patch"
    "github.com/afterdarksys/afterdark-darkd/internal/platform"
    "github.com/stretchr/testify/assert"
)

func TestClassifier_DetermineUrgency(t *testing.T) {
    tests := []struct {
        name     string
        patch    platform.Patch
        expected time.Duration
    }{
        {
            name: "critical severity gets 1 day",
            patch: platform.Patch{
                Severity: platform.SeverityCritical,
                Category: platform.CategorySoftware,
            },
            expected: 24 * time.Hour,
        },
        {
            name: "kernel category gets 2 days",
            patch: platform.Patch{
                Severity: platform.SeverityImportant,
                Category: platform.CategoryKernel,
            },
            expected: 48 * time.Hour,
        },
        // Add more test cases
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            classifier := patch.NewClassifier()
            urgency := classifier.DetermineUrgency(tt.patch)
            assert.Equal(t, tt.expected, urgency)
        })
    }
}
```

### Integration Tests

```go
// Example: test/integration/daemon_test.go
// +build integration

package integration_test

import (
    "context"
    "testing"
    "time"

    "github.com/afterdarksys/afterdark-darkd/internal/daemon"
    "github.com/stretchr/testify/require"
)

func TestDaemon_StartStop(t *testing.T) {
    // Create test config
    cfg := &daemon.Config{
        // test configuration
    }

    d, err := daemon.New(cfg)
    require.NoError(t, err)

    ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
    defer cancel()

    // Start daemon
    err = d.Start(ctx)
    require.NoError(t, err)

    // Verify daemon is running
    status := d.Status()
    require.Equal(t, "running", status)

    // Stop daemon
    err = d.Stop(ctx)
    require.NoError(t, err)
}
```

## Next Steps

1. **Complete TICKET-001**: Initialize project structure (DONE)
2. **Start TICKET-002**: Set up build system
3. **Begin TICKET-004**: Implement daemon lifecycle
4. **Follow ROADMAP.md**: Progress through milestones sequentially

## Resources

- [Go Documentation](https://golang.org/doc/)
- [Effective Go](https://golang.org/doc/effective_go)
- [Go Code Review Comments](https://github.com/golang/go/wiki/CodeReviewComments)
- [gRPC Go Quick Start](https://grpc.io/docs/languages/go/quickstart/)
- [Testify Documentation](https://github.com/stretchr/testify)

## Support

For questions or issues during development:
1. Check ARCHITECTURE.md for design decisions
2. Review ROADMAP.md for implementation sequence
3. Consult team lead or architect
4. Create design document for significant changes
