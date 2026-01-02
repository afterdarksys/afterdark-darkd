# AfterDark-DarkD

Enterprise endpoint security daemon for patch compliance, threat intelligence, and baseline security monitoring.

## Overview

AfterDark-DarkD is a cross-platform security agent that provides:

- **Patch Compliance Monitoring** - Track installed vs. available patches with urgency-based SLAs
- **Threat Intelligence** - Real-time bad domain/IP detection via DarkAPI.io integration
- **Baseline Security** - Application inventory and vulnerability assessment
- **Network Controls** - DNS enforcement, ICMP blocking, IP fragmentation protection

## Supported Platforms

| Platform | Version | Status |
|----------|---------|--------|
| macOS | 12+ (Intel/ARM) | Supported |
| Windows | 10/11, Server 2019+ | Supported |
| RHEL/Rocky | 8, 9 | Supported |
| Debian | 11, 12 | Supported |
| Ubuntu | 20.04, 22.04, 24.04 | Supported |

## Components

| Binary | Description |
|--------|-------------|
| `afterdark-darkd` | Main security daemon |
| `afterdark-darkdadm` | Administrative CLI |
| `darkapi` | End-user security status CLI |

## Quick Start

### Build from Source

```bash
# Clone repository
git clone https://github.com/afterdarksys/afterdark-darkd.git
cd afterdark-darkd

# Build all binaries
make build

# Run tests
make test
```

### Install

```bash
# Install binaries
sudo make install

# Configure
sudo cp configs/darkd.yaml.example /etc/afterdark/darkd.yaml
sudo vim /etc/afterdark/darkd.yaml

# Set API key
export DARKAPI_API_KEY="your-key-here"

# Start daemon
sudo afterdark-darkd --config /etc/afterdark/darkd.yaml
```

See [INSTALL](INSTALL) for detailed installation instructions.

## Configuration

```yaml
daemon:
  log_level: info
  data_dir: /var/lib/afterdark

services:
  patch_monitor:
    enabled: true
    scan_interval: 1h
    urgency_tiers:
      critical: 24h        # 1 day for critical/exploit
      kernel_network: 48h  # 2 days for kernel/network
      software: 72h        # 3 days for software
      windows_standard: 168h # 7 days for Windows

  threat_intel:
    enabled: true
    sync_interval: 6h

  network_monitor:
    enabled: true
    dns_servers:
      - cache01.dnsscience.io
      - cache02.dnsscience.io
    allow_icmp: false
    block_fragmentation: true
```

## Usage

### Check Security Status

```bash
# End-user status
darkapi status

# Detailed admin status
afterdark-darkdadm status
```

### Patch Management

```bash
# List missing patches
afterdark-darkdadm patches list

# Check compliance
afterdark-darkdadm patches compliance

# Trigger scan
afterdark-darkdadm patches scan
```

### Threat Intelligence

```bash
# Check domain
darkapi check domain example.com

# Check IP
darkapi check ip 192.168.1.1

# Sync threat intel
afterdark-darkdadm threats sync
```

## API Integrations

| Service | Purpose |
|---------|---------|
| api.afterdarksys.com | Patch intelligence, endpoint management |
| api.darkapi.io | Threat intelligence (bad domains/IPs) |
| api.dnsscience.io | DNS security and caching |
| api.veribits.com | Identity verification |

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    afterdark-darkd                       │
├─────────────────────────────────────────────────────────┤
│  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐        │
│  │   Patch     │ │   Threat    │ │  Baseline   │        │
│  │  Monitor    │ │   Intel     │ │  Scanner    │        │
│  └──────┬──────┘ └──────┬──────┘ └──────┬──────┘        │
│         │               │               │                │
│  ┌──────┴───────────────┴───────────────┴──────┐        │
│  │              Service Registry                │        │
│  └──────────────────────┬───────────────────────┘        │
│                         │                                │
│  ┌──────────────────────┴───────────────────────┐        │
│  │           Platform Abstraction               │        │
│  │     (macOS / Windows / Linux)                │        │
│  └──────────────────────────────────────────────┘        │
├─────────────────────────────────────────────────────────┤
│  Storage (JSON)  │  IPC (gRPC)  │  API Clients          │
└─────────────────────────────────────────────────────────┘
```

## Development

```bash
# Format code
make fmt

# Run linter
make lint

# Run tests with coverage
make coverage

# Build for all platforms
make build-all
```

## Deployment

Infrastructure as code is available for automated deployment:

- **Ansible**: `deployments/ansible/` - Playbooks for all supported platforms
- **Terraform**: `deployments/terraform/` - AWS, Azure, GCP modules

See [deployments/README.md](deployments/README.md) for details.

## Documentation

| Document | Description |
|----------|-------------|
| [INSTALL](INSTALL) | Installation guide |
| [ARCHITECTURE.md](ARCHITECTURE.md) | System design |
| [ROADMAP.md](ROADMAP.md) | Development roadmap |
| [TODO](TODO) | Current priorities |

## License

MIT License - see [LICENSE](LICENSE)

## Support

- Documentation: https://docs.afterdarksys.com/darkd
- Issues: https://github.com/afterdarksys/afterdark-darkd/issues
- Email: support@afterdarksys.com

---

After Dark Systems, LLC
