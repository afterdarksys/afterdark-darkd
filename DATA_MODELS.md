# AfterDark-DarkD Data Models

## Overview

This document defines the complete data model structure for AfterDark-DarkD, including JSON storage schema, API request/response formats, and internal data structures.

## Storage Schema

### Primary Data Structure

The daemon stores data in a hierarchical JSON structure:

```
/var/lib/afterdark/data/
├── system.json           # System information
├── patches.json          # Patch scan results
├── applications.json     # Application inventory
├── threats.json          # Threat intelligence cache
├── baseline.json         # Baseline scan results
├── network.json          # Network configuration
├── compliance.json       # Compliance status
└── reports/              # Generated reports
    ├── YYYY-MM-DD/
    │   ├── compliance.json
    │   ├── exposure.json
    │   └── summary.json
    └── latest -> YYYY-MM-DD
```

### 1. System Information (system.json)

```json
{
  "version": "1.0",
  "collected_at": "2026-01-02T10:30:00Z",
  "system": {
    "hostname": "workstation-001",
    "os": {
      "name": "macOS",
      "version": "14.2.1",
      "build": "23C71",
      "architecture": "arm64",
      "kernel": "Darwin 23.2.0"
    },
    "hardware": {
      "cpu": "Apple M2",
      "cores": 8,
      "memory_total_gb": 16,
      "disk_total_gb": 512,
      "disk_free_gb": 256
    },
    "network": {
      "hostname": "workstation-001.internal.example.com",
      "public_ip": "203.0.113.42",
      "private_ips": ["192.168.1.100", "fe80::1"],
      "interfaces": [
        {
          "name": "en0",
          "mac": "00:11:22:33:44:55",
          "ipv4": "192.168.1.100",
          "ipv6": "fe80::1",
          "status": "up"
        }
      ],
      "dns_servers": [
        "cache01.dnsscience.io",
        "cache02.dnsscience.io"
      ]
    }
  }
}
```

### 2. Patch Data (patches.json)

```json
{
  "version": "1.0",
  "last_scan": "2026-01-02T10:30:00Z",
  "next_scan": "2026-01-02T11:30:00Z",
  "scan_duration_seconds": 28.5,
  "summary": {
    "total_installed": 142,
    "total_available": 8,
    "by_severity": {
      "critical": 2,
      "important": 3,
      "moderate": 2,
      "low": 1
    },
    "by_category": {
      "kernel": 1,
      "network": 1,
      "security": 4,
      "software": 2
    },
    "overdue": {
      "1_day": 2,
      "2_day": 1,
      "3_day": 0,
      "7_day": 0
    }
  },
  "installed_patches": [
    {
      "id": "KB5034441",
      "name": "2024-01 Cumulative Update for Windows 11",
      "description": "Security updates for Windows 11",
      "severity": "critical",
      "category": "security",
      "installed_at": "2026-01-01T14:23:00Z",
      "released_at": "2026-01-01T00:00:00Z",
      "size_bytes": 524288000,
      "cves": [
        "CVE-2024-12345",
        "CVE-2024-12346"
      ],
      "kb_article": "KB5034441",
      "reboot_required": false
    }
  ],
  "available_patches": [
    {
      "id": "KB5034500",
      "name": "2024-01 Security Update",
      "description": "Critical security update",
      "severity": "critical",
      "category": "security",
      "released_at": "2026-01-02T00:00:00Z",
      "size_bytes": 125829120,
      "cves": [
        "CVE-2024-99999"
      ],
      "kb_article": "KB5034500",
      "exploit_detected": true,
      "urgency": {
        "tier": 1,
        "due_date": "2026-01-03T00:00:00Z",
        "hours_remaining": 13.5,
        "reason": "Critical severity with active exploit"
      },
      "reboot_required": true,
      "supersedes": ["KB5034441"]
    }
  ],
  "metadata": {
    "source": "windows_update",
    "scan_method": "wmi",
    "errors": []
  }
}
```

### 3. Application Inventory (applications.json)

```json
{
  "version": "1.0",
  "last_scan": "2026-01-02T10:30:00Z",
  "summary": {
    "total_applications": 87,
    "with_vulnerabilities": 5,
    "with_active_exploits": 1
  },
  "applications": [
    {
      "id": "app-001",
      "name": "Google Chrome",
      "version": "120.0.6099.129",
      "vendor": "Google LLC",
      "install_date": "2025-11-15T09:00:00Z",
      "install_path": "/Applications/Google Chrome.app",
      "size_bytes": 367001600,
      "architecture": "universal",
      "vulnerabilities": [
        {
          "cve": "CVE-2024-12345",
          "cvss_score": 8.8,
          "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H",
          "severity": "high",
          "description": "Use-after-free in rendering engine",
          "exploit_available": true,
          "exploit_public": true,
          "patch_available": true,
          "fixed_version": "120.0.6099.130"
        }
      ],
      "update_available": {
        "version": "120.0.6099.130",
        "released_at": "2026-01-01T00:00:00Z",
        "download_url": "https://dl.google.com/chrome/mac/stable/..."
      }
    }
  ],
  "metadata": {
    "scan_method": "system_profiler",
    "sources": ["applications_folder", "homebrew", "system_profiler"]
  }
}
```

### 4. Threat Intelligence (threats.json)

```json
{
  "version": "1.0",
  "last_sync": "2026-01-02T08:00:00Z",
  "next_sync": "2026-01-02T14:00:00Z",
  "sync_duration_seconds": 2.3,
  "summary": {
    "total_domains": 125847,
    "total_ips": 45623,
    "total_hashes": 892341,
    "sources": ["darkapi", "veribits", "dnsscience"]
  },
  "domains": {
    "index_file": "threats_domains.idx",
    "data_file": "threats_domains.dat",
    "count": 125847,
    "samples": [
      {
        "domain": "malicious.example.com",
        "first_seen": "2026-01-01T12:00:00Z",
        "last_seen": "2026-01-02T08:00:00Z",
        "severity": "high",
        "categories": ["phishing", "malware-distribution"],
        "sources": ["darkapi", "veribits"],
        "description": "Known phishing domain targeting financial institutions"
      }
    ]
  },
  "ips": {
    "index_file": "threats_ips.idx",
    "data_file": "threats_ips.dat",
    "count": 45623,
    "cidrs": [
      {
        "cidr": "198.51.100.0/24",
        "first_seen": "2026-01-01T00:00:00Z",
        "last_seen": "2026-01-02T08:00:00Z",
        "severity": "critical",
        "categories": ["c2-server", "botnet"],
        "sources": ["darkapi"],
        "description": "Botnet command and control infrastructure"
      }
    ]
  },
  "metadata": {
    "api_version": "2.0",
    "sync_type": "incremental",
    "errors": []
  }
}
```

### 5. Baseline Scan (baseline.json)

```json
{
  "version": "1.0",
  "baseline_date": "2026-01-01T00:00:00Z",
  "last_comparison": "2026-01-02T10:30:00Z",
  "baseline": {
    "applications": {
      "count": 85,
      "checksum": "sha256:abcdef123456...",
      "snapshot_file": "baseline_apps_2026-01-01.json"
    },
    "patches": {
      "count": 140,
      "checksum": "sha256:123456abcdef...",
      "snapshot_file": "baseline_patches_2026-01-01.json"
    },
    "network": {
      "interfaces": 2,
      "dns_servers": ["cache01.dnsscience.io", "cache02.dnsscience.io"],
      "checksum": "sha256:fedcba654321...",
      "snapshot_file": "baseline_network_2026-01-01.json"
    }
  },
  "changes": {
    "applications": {
      "added": [
        {
          "name": "Slack",
          "version": "4.36.134",
          "install_date": "2026-01-02T09:15:00Z"
        }
      ],
      "removed": [
        {
          "name": "OldApp",
          "version": "1.0.0",
          "removal_date": "2026-01-02T08:00:00Z"
        }
      ],
      "updated": [
        {
          "name": "Google Chrome",
          "old_version": "120.0.6099.129",
          "new_version": "120.0.6099.130",
          "update_date": "2026-01-02T10:00:00Z"
        }
      ]
    },
    "patches": {
      "installed": 2,
      "details": [
        {
          "id": "KB5034500",
          "installed_at": "2026-01-02T09:30:00Z"
        }
      ]
    }
  },
  "risk_assessment": {
    "risk_score": 6.5,
    "risk_level": "medium",
    "factors": [
      {
        "factor": "unauthorized_application",
        "impact": "medium",
        "description": "Application installed outside of approved process"
      }
    ]
  }
}
```

### 6. Network Configuration (network.json)

```json
{
  "version": "1.0",
  "last_updated": "2026-01-02T10:30:00Z",
  "settings": {
    "dns": {
      "mode": "managed",
      "servers": [
        "cache01.dnsscience.io",
        "cache02.dnsscience.io",
        "cache03.dnsscience.io",
        "cache04.dnsscience.io"
      ],
      "fallback_servers": ["1.1.1.1", "8.8.8.8"],
      "last_verified": "2026-01-02T10:30:00Z",
      "verification_status": "ok"
    },
    "icmp": {
      "ping_allowed": false,
      "traceroute_allowed": false,
      "enforcement_method": "firewall",
      "last_applied": "2026-01-01T00:00:00Z"
    },
    "fragmentation": {
      "fragmented_packets_blocked": true,
      "enforcement_method": "firewall",
      "last_applied": "2026-01-01T00:00:00Z"
    }
  },
  "monitoring": {
    "dns_queries": {
      "total_today": 15234,
      "blocked_malicious": 12,
      "blocked_domains": [
        {
          "domain": "malicious.example.com",
          "blocked_at": "2026-01-02T10:15:00Z",
          "threat_category": "phishing"
        }
      ]
    },
    "icmp_attempts": {
      "total_today": 3,
      "blocked": 3,
      "sources": ["192.168.1.50", "192.168.1.75"]
    }
  }
}
```

### 7. Compliance Status (compliance.json)

```json
{
  "version": "1.0",
  "as_of": "2026-01-02T10:30:00Z",
  "overall": {
    "compliant": false,
    "compliance_score": 85.5,
    "risk_level": "medium"
  },
  "patches": {
    "compliant": false,
    "total_missing": 8,
    "overdue": [
      {
        "id": "KB5034500",
        "name": "2024-01 Security Update",
        "severity": "critical",
        "due_date": "2026-01-03T00:00:00Z",
        "hours_overdue": 0,
        "urgency_tier": 1,
        "reason": "Critical with active exploit"
      }
    ],
    "upcoming_deadlines": [
      {
        "id": "KB5034501",
        "name": "Kernel Update",
        "severity": "important",
        "due_date": "2026-01-04T00:00:00Z",
        "hours_remaining": 37.5,
        "urgency_tier": 2
      }
    ],
    "compliance_by_tier": {
      "1_day": {
        "compliant": false,
        "required": 2,
        "missing": 2
      },
      "2_day": {
        "compliant": false,
        "required": 1,
        "missing": 1
      },
      "3_day": {
        "compliant": true,
        "required": 0,
        "missing": 0
      },
      "7_day": {
        "compliant": true,
        "required": 0,
        "missing": 0
      }
    }
  },
  "applications": {
    "compliant": false,
    "vulnerable_count": 5,
    "exploitable_count": 1,
    "details": [
      {
        "application": "Google Chrome",
        "version": "120.0.6099.129",
        "cve_count": 1,
        "max_cvss": 8.8,
        "exploit_available": true,
        "patch_available": true
      }
    ]
  },
  "network": {
    "compliant": true,
    "dns_configured": true,
    "icmp_blocked": true,
    "fragmentation_blocked": true
  },
  "threat_intel": {
    "compliant": true,
    "last_sync": "2026-01-02T08:00:00Z",
    "sync_age_hours": 2.5,
    "max_age_hours": 6
  }
}
```

## API Data Models

### AfterDark Systems API (api.afterdarksys.com)

#### Endpoint: GET /api/v1/endpoint/patches

Request:
```json
{
  "endpoint_id": "workstation-001",
  "os_type": "windows",
  "os_version": "11",
  "architecture": "amd64",
  "installed_patches": ["KB5034441", "KB5034442"]
}
```

Response:
```json
{
  "status": "success",
  "data": {
    "available_patches": [
      {
        "id": "KB5034500",
        "title": "2024-01 Security Update",
        "description": "Critical security update for Windows 11",
        "severity": "critical",
        "category": "security",
        "released_date": "2026-01-02T00:00:00Z",
        "kb_article": "KB5034500",
        "download_url": "https://catalog.update.microsoft.com/...",
        "size_bytes": 125829120,
        "cves": [
          {
            "id": "CVE-2024-99999",
            "cvss_score": 9.8,
            "exploit_available": true,
            "description": "Remote code execution vulnerability"
          }
        ],
        "supersedes": ["KB5034441"],
        "reboot_required": true
      }
    ],
    "recommendations": [
      {
        "patch_id": "KB5034500",
        "priority": "urgent",
        "install_by": "2026-01-03T00:00:00Z",
        "reason": "Active exploit detected in the wild"
      }
    ]
  },
  "metadata": {
    "timestamp": "2026-01-02T10:30:00Z",
    "api_version": "1.0"
  }
}
```

### DarkAPI.io (api.darkapi.io)

#### Endpoint: GET /api/v1/threat/domains

Request:
```http
GET /api/v1/threat/domains?since=2026-01-02T06:00:00Z&limit=10000
Authorization: Bearer <api_key>
```

Response:
```json
{
  "status": "success",
  "data": {
    "domains": [
      {
        "domain": "malicious.example.com",
        "first_seen": "2026-01-01T12:00:00Z",
        "last_seen": "2026-01-02T08:00:00Z",
        "severity": "high",
        "confidence": 95,
        "categories": ["phishing", "malware-distribution"],
        "tags": ["financial", "credential-theft"],
        "description": "Phishing domain targeting financial institutions",
        "iocs": {
          "ips": ["198.51.100.10", "198.51.100.11"],
          "nameservers": ["ns1.malicious.com", "ns2.malicious.com"]
        }
      }
    ],
    "pagination": {
      "total": 125847,
      "limit": 10000,
      "offset": 0,
      "has_more": true,
      "next_token": "eyJvZmZzZXQiOjEwMDAwfQ=="
    }
  },
  "metadata": {
    "timestamp": "2026-01-02T10:30:00Z",
    "api_version": "2.0",
    "sources": ["darkapi-intel", "veribits", "dnsscience"]
  }
}
```

#### Endpoint: GET /api/v1/threat/ips

Response structure similar to domains endpoint.

### DNSScience.io (api.dnsscience.io)

#### Endpoint: GET /api/v1/cache/health

Response:
```json
{
  "status": "success",
  "servers": [
    {
      "hostname": "cache01.dnsscience.io",
      "ip": "203.0.113.10",
      "status": "online",
      "latency_ms": 12.5,
      "load": 35.2,
      "queries_per_second": 15234
    },
    {
      "hostname": "cache02.dnsscience.io",
      "ip": "203.0.113.11",
      "status": "online",
      "latency_ms": 15.3,
      "load": 42.1,
      "queries_per_second": 18762
    }
  ]
}
```

### Veribits.com (api.veribits.com)

#### Endpoint: POST /api/v1/identity/verify

Request:
```json
{
  "endpoint_id": "workstation-001",
  "hostname": "workstation-001.internal.example.com",
  "public_key": "ssh-rsa AAAAB3NzaC1yc2EA...",
  "timestamp": "2026-01-02T10:30:00Z"
}
```

Response:
```json
{
  "status": "success",
  "data": {
    "verified": true,
    "endpoint_id": "workstation-001",
    "organization": "Example Corp",
    "tier": "enterprise",
    "features": ["threat-intel", "compliance", "reporting"],
    "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
    "expires_at": "2026-01-03T10:30:00Z"
  }
}
```

## Internal Data Structures

### Patch Classifier Decision Tree

```go
type UrgencyDecision struct {
    Tier        int           // 1, 2, 3, or 7
    Duration    time.Duration // 24h, 48h, 72h, 168h
    Reason      string
    Confidence  float64       // 0.0 to 1.0
}

func (c *Classifier) Classify(patch Patch) UrgencyDecision {
    // Priority 1: Exploit + Critical/Major
    if patch.ExploitActive &&
       (patch.Severity == SeverityCritical || patch.Severity == SeverityMajor) {
        return UrgencyDecision{
            Tier: 1,
            Duration: 24 * time.Hour,
            Reason: "Critical/Major severity with active exploit",
            Confidence: 1.0,
        }
    }

    // Priority 2: Kernel or Network
    if patch.Category == CategoryKernel || patch.Category == CategoryNetwork {
        return UrgencyDecision{
            Tier: 2,
            Duration: 48 * time.Hour,
            Reason: "Kernel or Network related patch",
            Confidence: 0.9,
        }
    }

    // Priority 3: Software patches
    if patch.Category == CategorySoftware {
        return UrgencyDecision{
            Tier: 3,
            Duration: 72 * time.Hour,
            Reason: "Software patch",
            Confidence: 0.8,
        }
    }

    // Priority 4: Windows standard (7 days)
    if patch.OSType == "windows" {
        return UrgencyDecision{
            Tier: 7,
            Duration: 168 * time.Hour,
            Reason: "Windows standard patch",
            Confidence: 0.7,
        }
    }

    // Default fallback
    return UrgencyDecision{
        Tier: 7,
        Duration: 168 * time.Hour,
        Reason: "Default urgency tier",
        Confidence: 0.5,
    }
}
```

### Threat Lookup Cache Structure

```go
// Optimized for fast lookups
type ThreatCache struct {
    domains *DomainTrie      // Trie structure for domain matching
    ips     *IPRangeTree     // Interval tree for CIDR matching
    hashes  map[string]*ThreatInfo  // Hash map for exact matches
    stats   CacheStats
}

type CacheStats struct {
    TotalDomains    int64
    TotalIPs        int64
    TotalHashes     int64
    LastSync        time.Time
    HitRate         float64
    QueriesPerSec   float64
}

// Domain trie for efficient subdomain matching
type DomainTrie struct {
    root *TrieNode
}

type TrieNode struct {
    children map[string]*TrieNode
    threat   *ThreatInfo  // nil if not a threat
}

// IP range tree for CIDR matching
type IPRangeTree struct {
    ipv4 *IntervalTree
    ipv6 *IntervalTree
}
```

## Data Retention Policy

| Data Type | Retention Period | Cleanup Strategy |
|-----------|------------------|------------------|
| System info | Current + 30 days history | Rolling window |
| Patch scans | Current + 90 days history | Rolling window |
| Application inventory | Current + 90 days snapshots | Weekly snapshots |
| Threat intel | Current + sync cycle | Replace on sync |
| Baseline | Current + all historical | Manual cleanup |
| Compliance | Current + 365 days | Rolling window |
| Reports | Current + 365 days | Archival to compressed storage |
| Audit logs | Current + 2 years | Append-only, compressed |

## Storage Optimization

### Compression
- JSON files compressed with gzip
- Compression ratio target: 70-80% reduction
- Transparent decompression on read

### Indexing
- In-memory indexes for fast queries
- Rebuild indexes on daemon start
- Periodic index optimization

### Caching
- LRU cache for frequently accessed data
- Cache size: 100MB default
- TTL: Configurable per data type

### Cleanup
- Automated cleanup based on retention policy
- Manual cleanup command via CLI
- Backup before cleanup (optional)

## Data Migration

### Version 1.0 → 1.1 (Example)

```go
type Migrator struct {
    from string
    to   string
}

func (m *Migrator) Migrate(dataDir string) error {
    // 1. Backup current data
    if err := m.backup(dataDir); err != nil {
        return err
    }

    // 2. Transform data structures
    if err := m.transform(dataDir); err != nil {
        return m.rollback(dataDir)
    }

    // 3. Validate migrated data
    if err := m.validate(dataDir); err != nil {
        return m.rollback(dataDir)
    }

    return nil
}
```

## Query Examples

### Find all critical patches due within 24 hours

```json
{
  "collection": "patches",
  "filter": {
    "severity": "critical",
    "urgency.tier": 1,
    "urgency.hours_remaining": {"$lt": 24}
  },
  "sort": [
    {"field": "urgency.hours_remaining", "order": "asc"}
  ]
}
```

### Find applications with exploitable vulnerabilities

```json
{
  "collection": "applications",
  "filter": {
    "vulnerabilities": {
      "$elemMatch": {
        "exploit_available": true,
        "cvss_score": {"$gte": 7.0}
      }
    }
  },
  "sort": [
    {"field": "vulnerabilities.cvss_score", "order": "desc"}
  ]
}
```

### Compliance history trend (last 30 days)

```json
{
  "collection": "compliance_history",
  "filter": {
    "as_of": {
      "$gte": "2025-12-03T00:00:00Z",
      "$lte": "2026-01-02T00:00:00Z"
    }
  },
  "fields": ["as_of", "overall.compliance_score"],
  "sort": [
    {"field": "as_of", "order": "asc"}
  ]
}
```
