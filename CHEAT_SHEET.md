# AfterDark-DarkD Quick Reference

## Project Structure at a Glance

```
afterdark-darkd/
├── cmd/                      # Executable entry points
│   ├── afterdark-darkd/     # Main daemon (runs as service)
│   ├── afterdark-darkdadm/  # Admin CLI (root/admin users)
│   └── darkapi/             # User CLI (end users)
│
├── internal/                 # Private application code
│   ├── daemon/              # Daemon lifecycle, config, health
│   ├── service/             # 5 core services (patch, threat, etc.)
│   ├── platform/            # OS abstraction (macOS/Win/Linux)
│   ├── api/                 # External API clients (8+ integrations)
│   ├── storage/             # JSON store, cache, audit log
│   ├── ipc/                 # gRPC server for CLI communication
│   └── models/              # Data structures
│
├── pkg/                      # Reusable libraries
│   ├── logging/             # Structured logging
│   ├── metrics/             # Performance metrics
│   └── retry/               # Retry logic
│
└── docs/                     # See below for documentation index
```

## Documentation Quick Index

| Doc | What's Inside | When to Use |
|-----|---------------|-------------|
| **README** | Original requirements | Understanding project goals |
| **IMPLEMENTATION_SUMMARY.md** | Executive overview, timeline | Start here for big picture |
| **QUICK_START.md** | Setup guide, first code | Getting started coding |
| **ARCHITECTURE.md** | Design, interfaces, components | Understanding system design |
| **ROADMAP.md** | 69 tickets, 10 milestones | Planning sprints, tracking work |
| **DATA_MODELS.md** | JSON schemas, API formats | Working with data structures |
| **CROSS_PLATFORM.md** | Platform-specific code | Implementing OS features |
| **CHEAT_SHEET.md** | This file - quick reference | Quick lookups |

## Core Components Quick Reference

### 5 Core Services

```
┌──────────────────┬───────────────────────────────────────────┐
│ Service          │ Purpose                                    │
├──────────────────┼───────────────────────────────────────────┤
│ Patch Monitor    │ Scan patches, classify urgency, auto-    │
│                  │ install (Windows), track compliance       │
├──────────────────┼───────────────────────────────────────────┤
│ Threat Intel     │ Sync bad domains/IPs, fast lookups,       │
│                  │ cache management                          │
├──────────────────┼───────────────────────────────────────────┤
│ Baseline Scanner │ App inventory, vulnerability assessment,  │
│                  │ exploit detection, change tracking        │
├──────────────────┼───────────────────────────────────────────┤
│ Network Monitor  │ DNS enforcement, ICMP control, IP frag    │
│                  │ detection, public IP tracking             │
├──────────────────┼───────────────────────────────────────────┤
│ Report Generator │ Compliance reports, exposure analysis,    │
│                  │ trend tracking (JSON/HTML/PDF)            │
└──────────────────┴───────────────────────────────────────────┘
```

### 5 Supported Platforms

```
┌────────────┬─────────────┬────────────────────────────────┐
│ Platform   │ Package     │ Key Tools                       │
├────────────┼─────────────┼────────────────────────────────┤
│ macOS      │ .pkg        │ softwareupdate, system_profiler│
│            │             │ networksetup, launchd           │
├────────────┼─────────────┼────────────────────────────────┤
│ Windows    │ .msi        │ WMI, Windows Update API,        │
│            │             │ Registry, PowerShell, Service   │
├────────────┼─────────────┼────────────────────────────────┤
│ Debian/    │ .deb        │ apt, dpkg, unattended-upgrades,│
│ Ubuntu     │             │ systemd                         │
├────────────┼─────────────┼────────────────────────────────┤
│ RHEL/Rocky │ .rpm        │ dnf/yum, rpm, yum-security,    │
│            │             │ systemd                         │
├────────────┼─────────────┼────────────────────────────────┤
│ All        │ Docker      │ Container deployment (optional) │
└────────────┴─────────────┴────────────────────────────────┘
```

### 8+ External APIs

```
┌───────────────────────┬──────────────────────────────────┐
│ API                   │ Purpose                           │
├───────────────────────┼──────────────────────────────────┤
│ api.afterdarksys.com  │ Endpoint patch intelligence       │
│ api.darkapi.io        │ Threat intel (domains, IPs)       │
│ api.dnsscience.io     │ Secure DNS services               │
│ api.veribits.com      │ Identity verification             │
│ systemapi.io          │ System management integration     │
│ computeapi.io         │ Compute infrastructure            │
│ planetapi.io          │ Global infrastructure             │
│ nextapi.io            │ Next-gen services                 │
│ aeims.app             │ Enterprise monitoring             │
│ OCI observability     │ Cloud-native observability        │
└───────────────────────┴──────────────────────────────────┘
```

## Patch Urgency Tiers (Critical Feature)

```
┌──────┬──────────────┬─────────────────────────────────────┐
│ Tier │ Deadline     │ Criteria                             │
├──────┼──────────────┼─────────────────────────────────────┤
│  1   │ 24 hours     │ CRITICAL/MAJOR + Active Exploit      │
├──────┼──────────────┼─────────────────────────────────────┤
│  2   │ 48 hours     │ Kernel or Network patches            │
├──────┼──────────────┼─────────────────────────────────────┤
│  3   │ 72 hours     │ Software patches                     │
├──────┼──────────────┼─────────────────────────────────────┤
│  7   │ 7 days       │ Windows patches (auto-install opt)   │
└──────┴──────────────┴─────────────────────────────────────┘
```

## Key Commands (Make Targets)

```bash
# Development
make deps          # Download dependencies
make build         # Build all binaries
make test          # Run unit tests
make coverage      # Generate coverage report
make fmt           # Format code
make lint          # Run linters

# Testing
make integration   # Run integration tests
make bench         # Run benchmarks

# Build
make build-all     # Cross-compile for all platforms
make clean         # Clean build artifacts

# Installation
make install       # Install binaries to /usr/local/bin
```

## CLI Commands Overview

### Admin CLI (darkdadm)

```bash
# Daemon control
darkdadm status                    # Show daemon status
darkdadm service start|stop|restart

# Scans
darkdadm scan patches             # Trigger patch scan
darkdadm scan baseline            # Trigger baseline scan

# Viewing data
darkdadm patches list             # List all patches
darkdadm patches missing          # Show missing patches
darkdadm threats domains          # List bad domains
darkdadm threats ips              # List bad IPs
darkdadm baseline apps            # Application inventory

# Reports
darkdadm report compliance        # Compliance report
darkdadm report exposure          # Exposure analysis

# Configuration
darkdadm config show              # Show current config
darkdadm config set <key> <value> # Update config
```

### User CLI (darkapi)

```bash
# Status
darkapi status                    # Security status overview

# Checks
darkapi patches                   # Missing patches summary
darkapi check domain example.com  # Check if domain is malicious
darkapi check ip 1.2.3.4         # Check if IP is malicious

# Reports
darkapi report                    # Latest security report
```

## File Locations

```bash
# macOS
/etc/afterdark/darkd.yaml         # Configuration
/var/lib/afterdark/               # Data storage
/var/log/afterdark/               # Logs
/var/run/afterdark/darkd.sock     # IPC socket

# Windows
C:\ProgramData\AfterDark\darkd.yaml           # Config
C:\ProgramData\AfterDark\data\                # Data
C:\ProgramData\AfterDark\logs\                # Logs
\\.\pipe\afterdark-darkd                      # IPC pipe

# Linux
/etc/afterdark/darkd.yaml         # Configuration
/var/lib/afterdark/               # Data storage
/var/log/afterdark/               # Logs
/var/run/afterdark/darkd.sock     # IPC socket
```

## Data Storage Files

```bash
/var/lib/afterdark/data/
├── system.json           # System information
├── patches.json          # Patch scan results
├── applications.json     # App inventory
├── threats.json          # Threat intel cache
├── baseline.json         # Baseline scan results
├── network.json          # Network config
├── compliance.json       # Compliance status
└── reports/              # Generated reports
    └── YYYY-MM-DD/
```

## Development Workflow

```bash
# 1. Pick a ticket from ROADMAP.md
git checkout -b feature/TICKET-XXX-description

# 2. Write tests first
touch internal/service/patch/scanner_test.go
# Write test cases

# 3. Implement feature
# Write production code

# 4. Test
make test
make lint

# 5. Commit
git add .
git commit -m "TICKET-XXX: Brief description"

# 6. Push and create PR
git push origin feature/TICKET-XXX-description
```

## Project Timeline

```
Week 1-3   : Foundation (daemon, config, services)
Week 4-6   : Platform support (macOS, Windows, Linux)
Week 7     : Storage layer (JSON, cache, audit)
Week 8-9   : API clients (8+ integrations)
Week 10-13 : Core services (patch, threat, baseline, network, report)
Week 14-15 : IPC & CLIs (gRPC, darkdadm, darkapi)
Week 16    : Service installers (launchd, systemd, Windows Service)
Week 17-18 : Testing (integration, performance, security)
Week 19    : Documentation (user, operator, developer)
Week 20-22 : Beta testing and GA release

Total: 22 weeks (5.5 months)
```

## Critical Tickets (Must Complete First)

```
Phase 1 Foundation:
  TICKET-001  Initialize project structure          [2 hours]
  TICKET-002  Build system and cross-compilation    [4 hours]
  TICKET-004  Daemon lifecycle management           [8 hours]
  TICKET-005  Configuration management              [8 hours]
  TICKET-007  Service interface and registry        [6 hours]

Phase 2 Platform:
  TICKET-009  Platform interface definition         [6 hours]
  TICKET-010  macOS platform support                [16 hours]
  TICKET-011  Windows platform support              [20 hours]
  TICKET-012  Linux Debian/Ubuntu support           [12 hours]
  TICKET-013  Linux RHEL/Rocky support              [12 hours]
```

## Performance Targets

```
Memory Usage       : < 100 MB RSS
CPU Usage          : < 5% average, < 20% during scans
Patch Scan Time    : < 30 seconds
Threat Lookup      : < 1 millisecond
CLI Response       : < 100 milliseconds
Daemon Uptime      : 99.9% SLA
```

## Security Checklist

- [ ] All API calls over HTTPS/TLS 1.3+
- [ ] API keys encrypted at rest
- [ ] IPC authentication enabled
- [ ] File permissions: 600 for configs, 700 for data
- [ ] Audit logging for all privileged operations
- [ ] Input validation on all inputs
- [ ] No plaintext passwords in logs
- [ ] Regular security audits

## Testing Checklist

- [ ] Unit tests for all business logic (>80% coverage)
- [ ] Integration tests for service interactions
- [ ] Platform-specific tests on actual OS
- [ ] Performance benchmarks meet targets
- [ ] Security penetration testing complete
- [ ] E2E scenarios tested
- [ ] Load testing completed

## Common Issues and Solutions

### Build Issues
```bash
# Missing dependencies
make deps

# Cross-compilation fails
# Check GOOS and GOARCH environment variables
GOOS=darwin GOARCH=amd64 go build

# Module errors
go mod tidy
```

### Runtime Issues
```bash
# Permission denied
# Run as root/administrator
sudo afterdark-darkd

# Config not found
# Specify config path
afterdark-darkd --config /path/to/darkd.yaml

# Service won't start
# Check logs
tail -f /var/log/afterdark/darkd.log
```

### Platform-Specific

**macOS:**
```bash
# SIP (System Integrity Protection) blocks operations
# Disable SIP temporarily or use proper entitlements
```

**Windows:**
```bash
# WMI errors
# Run PowerShell as Administrator
# Restart WMI service: net stop winmgmt && net start winmgmt
```

**Linux:**
```bash
# Package manager locked
# Wait for other operations to complete
# Kill hung apt/dnf processes if necessary
```

## Resource Links

- Go Documentation: https://golang.org/doc/
- gRPC Go: https://grpc.io/docs/languages/go/
- Testify: https://github.com/stretchr/testify
- Cobra CLI: https://github.com/spf13/cobra
- Viper Config: https://github.com/spf13/viper

## Team Contacts

- Architecture: enterprise-systems-architect
- Engineering: ads-ai-staff engineering team
- Tickets: api.changes.afterdarksys.com

## Quick Reference Card

```
┌────────────────────────────────────────────────────────────┐
│ AfterDark-DarkD Quick Reference                            │
├────────────────────────────────────────────────────────────┤
│ Start Here:    IMPLEMENTATION_SUMMARY.md                   │
│ Setup:         QUICK_START.md                              │
│ Design:        ARCHITECTURE.md                             │
│ Planning:      ROADMAP.md (69 tickets)                     │
│ Data:          DATA_MODELS.md                              │
│ Platforms:     CROSS_PLATFORM.md                           │
│ Quick Ref:     This file                                   │
├────────────────────────────────────────────────────────────┤
│ Build:         make build                                  │
│ Test:          make test                                   │
│ Run:           ./afterdark-darkd --config darkd.yaml       │
├────────────────────────────────────────────────────────────┤
│ Timeline:      22 weeks to GA                              │
│ Team Size:     3-5 devs + QA + DevOps                      │
│ Next Action:   TICKET-001 (2 hours)                        │
└────────────────────────────────────────────────────────────┘
```

## Status: READY TO BEGIN

All architecture documents created.
Project structure defined.
Implementation plan complete.
Next step: Execute TICKET-001 from QUICK_START.md
