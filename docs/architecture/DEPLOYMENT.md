# AfterDark Deployment Architecture

This document describes the deployment architecture for afterdark-darkd across different user segments.

## Overview

AfterDark supports two primary deployment models:

1. **Home User** - Individual users protecting personal devices
2. **Enterprise** - Organizations managing fleets of endpoints

```
                                    ┌─────────────────────────────────┐
                                    │     AfterDark Cloud Portal      │
                                    │  (portal.afterdark.io)          │
                                    │                                 │
                                    │  - Account management           │
                                    │  - API key generation           │
                                    │  - Fleet management             │
                                    │  - Host templates               │
                                    │  - Asset inventory              │
                                    │  - Threat dashboard             │
                                    └─────────────────────────────────┘
                                                   │
                                                   │ HTTPS API
                                                   ▼
                    ┌──────────────────────────────────────────────────────┐
                    │                  AfterDark API                        │
                    │              (api.afterdark.io)                       │
                    │                                                       │
                    │  /v1/devices/enroll     - Device enrollment          │
                    │  /v1/devices/config     - Configuration sync         │
                    │  /v1/devices/heartbeat  - Health reporting           │
                    │  /v1/threat-intel       - Threat intelligence        │
                    │  /v1/fleet/*            - Enterprise fleet mgmt      │
                    └──────────────────────────────────────────────────────┘
                                                   │
                         ┌─────────────────────────┼─────────────────────────┐
                         │                         │                         │
                         ▼                         ▼                         ▼
              ┌──────────────────┐      ┌──────────────────┐      ┌──────────────────┐
              │   Home User      │      │   Enterprise     │      │   Cloud/VM       │
              │   Endpoint       │      │   Endpoint       │      │   Instance       │
              │                  │      │                  │      │                  │
              │ - darkd-config   │      │ - MDM deployed   │      │ - Auto-enrolled  │
              │   GUI helper     │      │ - Group policy   │      │   via metadata   │
              │ - Manual setup   │      │ - Fleet managed  │      │ - Terraform/ARM  │
              └──────────────────┘      └──────────────────┘      └──────────────────┘
```

---

## Home User Deployment

### Target Audience
- Individual users
- Small office/home office (SOHO)
- Tech-savvy consumers who want advanced protection

### Configuration Flow

```
User Journey:

1. Download installer from afterdark.io/download
                    │
                    ▼
2. Run installer (creates daemon + config GUI)
                    │
                    ▼
3. Launch darkd-config GUI
                    │
                    ▼
4. Create account or sign in at portal.afterdark.io
                    │
                    ▼
5. Generate API key in portal
                    │
                    ▼
6. Paste API key into darkd-config GUI
                    │
                    ▼
7. GUI saves key and activates daemon
                    │
                    ▼
8. Protection active!
```

### Components

| Component | Purpose |
|-----------|---------|
| `afterdark-darkd` | Main security daemon |
| `darkd-config` | Fyne-based GUI for configuration |
| `darkapi` | CLI for checking security status |

### Configuration Methods

1. **GUI Helper (Recommended)**
   - Cross-platform Fyne application
   - Guides user through setup
   - Shows security status dashboard

2. **CLI (Advanced Users)**
   ```bash
   afterdark-darkdadm config set-key YOUR_API_KEY
   afterdark-darkdadm service start
   ```

3. **Environment Variable**
   ```bash
   export AFTERDARK_API_KEY=ak_live_xxxxx
   afterdark-darkd
   ```

### Features Available

- Patch monitoring
- Basic threat intelligence
- Firewall management
- Connection tracking
- Security baseline scanning

---

## Enterprise Deployment

### Target Audience
- IT departments
- Managed service providers (MSPs)
- Security operations centers (SOCs)

### Deployment Flow

```
Enterprise Journey:

1. Create organization at portal.afterdark.io
                    │
                    ▼
2. Import asset inventory (or discover automatically)
                    │
                    ▼
3. Create host templates with security policies
                    │
                    ▼
4. Generate fleet enrollment tokens
                    │
                    ▼
5. Deploy agent via MDM/CM tool with token
                    │
                    ▼
6. Agents auto-enroll and receive configuration
                    │
                    ▼
7. Manage fleet from central dashboard
```

### Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                        Enterprise Management Portal                      │
│                                                                         │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐   │
│  │   Fleet     │  │    Host     │  │   Asset     │  │   Policy    │   │
│  │  Dashboard  │  │  Templates  │  │  Inventory  │  │  Manager    │   │
│  └─────────────┘  └─────────────┘  └─────────────┘  └─────────────┘   │
│                                                                         │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐   │
│  │  Threat     │  │   Report    │  │    SIEM     │  │    API      │   │
│  │  Center     │  │  Generator  │  │ Integration │  │    Keys     │   │
│  └─────────────┘  └─────────────┘  └─────────────┘  └─────────────┘   │
└─────────────────────────────────────────────────────────────────────────┘
                                     │
                                     │ Fleet API
                                     ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                         Deployment Methods                               │
│                                                                         │
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────────────┐ │
│  │   MDM/EMM       │  │  Config Mgmt    │  │  Cloud Native           │ │
│  │                 │  │                 │  │                         │ │
│  │  - Jamf Pro    │  │  - Ansible      │  │  - AWS EC2 Tags        │ │
│  │  - Intune      │  │  - Puppet       │  │  - Azure Tags          │ │
│  │  - Kandji      │  │  - Chef         │  │  - GCP Metadata        │ │
│  │  - Mosyle      │  │  - Salt         │  │  - Terraform           │ │
│  │  - VMware WS1  │  │                 │  │  - CloudFormation      │ │
│  └─────────────────┘  └─────────────────┘  └─────────────────────────┘ │
└─────────────────────────────────────────────────────────────────────────┘
                                     │
                                     ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                         Managed Endpoints                                │
│                                                                         │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐     │
│  │ Laptop   │ │ Desktop  │ │ Server   │ │ VM       │ │ Container│     │
│  │ macOS    │ │ Windows  │ │ Linux    │ │ Cloud    │ │ K8s Pod  │     │
│  └──────────┘ └──────────┘ └──────────┘ └──────────┘ └──────────┘     │
└─────────────────────────────────────────────────────────────────────────┘
```

### a) Fleet-Wide Deployment

Deploy to all endpoints in a fleet using your existing tooling:

**Ansible Example:**
```yaml
- name: Deploy AfterDark Agent
  hosts: all
  vars:
    afterdark_enroll_token: "{{ vault_afterdark_token }}"
  tasks:
    - name: Install agent package
      package:
        name: afterdark-darkd
        state: present

    - name: Write enrollment token
      copy:
        content: "{{ afterdark_enroll_token }}"
        dest: /etc/afterdark/enroll-token
        mode: '0600'

    - name: Start daemon
      service:
        name: afterdark-darkd
        state: started
        enabled: yes
```

**Terraform (AWS) Example:**
```hcl
resource "aws_instance" "server" {
  ami           = var.ami_id
  instance_type = "t3.medium"

  tags = {
    "afterdark-api-key" = var.afterdark_api_key
    "afterdark-fleet"   = "production-servers"
  }

  user_data = <<-EOF
    #!/bin/bash
    curl -fsSL https://get.afterdark.io | sh
    systemctl enable afterdark-darkd
    systemctl start afterdark-darkd
  EOF
}
```

### b) Host Templates

Define security configurations that can be applied to groups of hosts:

```json
{
  "template_id": "server-hardened",
  "name": "Hardened Server Template",
  "description": "Security configuration for production servers",
  "settings": {
    "firewall": {
      "enabled": true,
      "default_deny_inbound": true,
      "default_deny_outbound": false,
      "allowed_inbound_ports": [22, 443, 8443]
    },
    "patch_policy": {
      "critical_auto_apply": true,
      "reboot_window": "03:00-05:00",
      "max_days_outstanding": 7
    },
    "threat_intel": {
      "blocklist_sync_interval": "1h",
      "auto_block_high_threat": true
    },
    "monitoring": {
      "connection_tracking": true,
      "process_monitoring": true,
      "file_integrity": true
    }
  }
}
```

### c) Asset Inventory Integration

Import existing asset inventory from:

- **CMDB** (ServiceNow, BMC Helix)
- **Active Directory**
- **Cloud provider APIs** (AWS, Azure, GCP)
- **CSV/Excel import**
- **API push from MDM**

### d) API Key Management

Enterprise API keys support scopes and permissions:

```json
{
  "key_id": "ak_live_ent_xxxxx",
  "name": "Production Fleet Key",
  "created_at": "2024-01-15T10:00:00Z",
  "scopes": [
    "devices:read",
    "devices:write",
    "fleet:manage",
    "threat-intel:read",
    "config:push"
  ],
  "restrictions": {
    "ip_whitelist": ["10.0.0.0/8", "192.168.0.0/16"],
    "rate_limit": 10000,
    "allowed_fleets": ["production", "staging"]
  }
}
```

---

## Auto-Configuration System

The agent automatically discovers its configuration using this priority order:

```
Priority 1: Environment Variables
     │
     └──► AFTERDARK_API_KEY
     └──► AFTERDARK_API_ENDPOINT
     │
Priority 2: Configuration Files
     │
     └──► /etc/afterdark/api-key
     └──► C:\ProgramData\AfterDark\api-key
     │
Priority 3: Cloud Metadata
     │
     └──► AWS EC2 Tags (afterdark-api-key)
     └──► Azure Instance Tags
     └──► GCP Instance Metadata
     │
Priority 4: MDM Configuration
     │
     └──► Jamf Pro (managed preferences)
     └──► Intune (registry)
     │
Priority 5: Enrollment Token
     │
     └──► /etc/afterdark/enroll-token
     └──► Exchanges token for permanent API key
```

---

## Firewall Plugin Integration

The agent includes platform-specific firewall plugins:

| Platform | Firewall Backend | Plugin |
|----------|------------------|--------|
| Linux | nftables (preferred), iptables (fallback) | `firewall-linux` |
| macOS | pf (pfctl) | `firewall-macos` |
| Windows | Windows Firewall (netsh advfirewall) | `firewall-windows` |

### Firewall Features

- Block/unblock IP addresses
- Add/remove custom rules
- Sync threat intel blocklists
- Open/close ports
- Default deny policies
- Integration with connection tracking

### Threat Response Automation

```
Threat Detected ──► Connection Tracker
                          │
                          ▼
                   Threat Score > 80?
                          │
                    ┌─────┴─────┐
                    │ YES       │ NO
                    ▼           ▼
             Auto-block IP   Log & Alert
                    │
                    ▼
             Firewall Plugin
                    │
         ┌──────────┼──────────┐
         ▼          ▼          ▼
     iptables     pfctl      netsh
```

---

## Deployment Checklist

### Home User
- [ ] Download installer
- [ ] Create account at portal.afterdark.io
- [ ] Generate API key
- [ ] Run darkd-config and enter API key
- [ ] Verify daemon is running
- [ ] Check security status

### Enterprise
- [ ] Create organization account
- [ ] Import asset inventory
- [ ] Create host templates
- [ ] Generate enrollment tokens
- [ ] Configure MDM/CM deployment
- [ ] Deploy to test group
- [ ] Verify enrollment
- [ ] Roll out to production
- [ ] Set up SIEM integration
- [ ] Configure alerting

---

## Support Resources

- Documentation: https://docs.afterdark.io
- API Reference: https://api.afterdark.io/docs
- Support: support@afterdark.io
- Status: https://status.afterdark.io
