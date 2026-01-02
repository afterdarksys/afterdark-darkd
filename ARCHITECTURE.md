# AfterDark-DarkD Architecture

## Overview

AfterDark-DarkD is an enterprise-grade, cross-platform endpoint security daemon built in Go. It provides comprehensive patch compliance monitoring, threat intelligence integration, and baseline security assessments across macOS, Windows, and Linux systems.

## Core Interfaces

### 1. Service Interface (internal/service/service.go)

All core services implement this common interface for lifecycle management:

```go
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
    Status    string    // "healthy", "degraded", "unhealthy"
    Message   string
    LastCheck time.Time
    Metrics   map[string]interface{}
}
```

### 2. Platform Interface (internal/platform/platform.go)

OS abstraction for cross-platform operations:

```go
type Platform interface {
    // System Information
    GetOSInfo() (*OSInfo, error)
    GetHostname() (string, error)

    // Patch Management
    ListInstalledPatches() ([]Patch, error)
    ListAvailablePatches() ([]Patch, error)
    InstallPatch(patchID string) error

    // Application Inventory
    ListInstalledApplications() ([]Application, error)

    // Network Operations
    GetNetworkInterfaces() ([]NetworkInterface, error)
    GetPublicIP() (string, error)
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

type PatchCategory int

const (
    CategoryUnknown PatchCategory = iota
    CategoryKernel
    CategoryNetwork
    CategorySoftware
    CategorySecurity
)
```

### 3. Storage Interface (internal/storage/store.go)

```go
type Store interface {
    // Initialize the storage backend
    Initialize(ctx context.Context, config *Config) error

    // Close the storage backend
    Close() error

    // Save stores data with the given key
    Save(ctx context.Context, key string, data interface{}) error

    // Load retrieves data for the given key
    Load(ctx context.Context, key string, dest interface{}) error

    // Delete removes data for the given key
    Delete(ctx context.Context, key string) error

    // List returns all keys matching the prefix
    List(ctx context.Context, prefix string) ([]string, error)

    // Query performs a structured query (for JSON)
    Query(ctx context.Context, query *Query) ([]interface{}, error)
}

type Query struct {
    Collection string
    Filter     map[string]interface{}
    Sort       []SortField
    Limit      int
    Offset     int
}
```

### 4. API Client Interface (internal/api/client.go)

```go
type APIClient interface {
    // Get performs a GET request
    Get(ctx context.Context, path string, result interface{}) error

    // Post performs a POST request
    Post(ctx context.Context, path string, body, result interface{}) error

    // SetAuth configures authentication
    SetAuth(auth AuthMethod) error

    // GetRateLimits returns current rate limit status
    GetRateLimits() *RateLimitStatus
}

type AuthMethod interface {
    Apply(req *http.Request) error
}

type APIKeyAuth struct {
    Key       string
    HeaderKey string
}

func (a *APIKeyAuth) Apply(req *http.Request) error {
    req.Header.Set(a.HeaderKey, a.Key)
    return nil
}
```

### 5. Patch Monitor Service Interface

```go
type PatchMonitor interface {
    Service

    // ScanNow triggers an immediate patch scan
    ScanNow(ctx context.Context) (*ScanResult, error)

    // GetComplianceStatus returns current compliance state
    GetComplianceStatus() (*ComplianceStatus, error)

    // GetMissingPatches returns patches not yet installed
    GetMissingPatches(urgency *UrgencyLevel) ([]Patch, error)

    // AutoInstall enables/disables automatic installation
    AutoInstall(enabled bool) error
}

type ScanResult struct {
    StartTime       time.Time
    EndTime         time.Time
    PatchesFound    int
    PatchesInstalled int
    PatchesMissing  int
    Errors          []error
}

type ComplianceStatus struct {
    Compliant       bool
    LastScan        time.Time
    NextScan        time.Time
    CriticalMissing int
    MajorMissing    int
    TotalMissing    int
    UrgentActions   []UrgentAction
}

type UrgentAction struct {
    Patch       Patch
    DueBy       time.Time
    UrgencyDays int
    Reason      string
}

type UrgencyLevel int

const (
    Urgency1Day UrgencyLevel = 1  // MAJOR, CRITICAL, EXPLOIT ACTIVE
    Urgency2Day UrgencyLevel = 2  // Network or Kernel
    Urgency3Day UrgencyLevel = 3  // Software patches
    Urgency7Day UrgencyLevel = 7  // Windows auto-install
)
```

### 6. Threat Intel Service Interface

```go
type ThreatIntelService interface {
    Service

    // SyncNow triggers immediate threat intel update
    SyncNow(ctx context.Context) error

    // IsDomainMalicious checks if a domain is on the bad list
    IsDomainMalicious(domain string) (bool, *ThreatInfo)

    // IsIPMalicious checks if an IP is on the bad list
    IsIPMalicious(ip string) (bool, *ThreatInfo)

    // GetBadDomains returns all known bad domains
    GetBadDomains() []string

    // GetBadIPs returns all known bad IPs
    GetBadIPs() []string

    // GetLastSync returns last successful sync time
    GetLastSync() time.Time
}

type ThreatInfo struct {
    Indicator    string
    Type         ThreatType
    FirstSeen    time.Time
    LastSeen     time.Time
    Severity     string
    Categories   []string
    Sources      []string
    Description  string
}

type ThreatType int

const (
    ThreatTypeDomain ThreatType = iota
    ThreatTypeIP
    ThreatTypeHash
    ThreatTypeURL
)
```

## Component Responsibilities

### Daemon (internal/daemon/)

**Responsibilities:**
- Process lifecycle management (start, stop, reload)
- Configuration loading and validation
- Service orchestration and coordination
- Signal handling (SIGTERM, SIGHUP, etc.)
- Health monitoring and metrics collection
- Graceful shutdown with cleanup

**Key Files:**
- `daemon.go`: Main daemon struct and lifecycle
- `config.go`: Configuration parser and validator
- `signals.go`: OS signal handling
- `health.go`: Health check endpoints

### Services (internal/service/)

#### Patch Monitor Service
**Responsibilities:**
- Periodic scanning for installed and available patches
- Urgency classification based on severity and category
- Compliance tracking against time-based SLAs
- Automatic installation for Windows (optional)
- Integration with api.afterdarksys.com for patch intelligence

**Urgency Tiers:**
- 1 day: MAJOR, CRITICAL, EXPLOIT ACTIVE
- 2 days: Network or Kernel related
- 3 days: Software patches
- 7 days: Windows patches (with auto-install option)

#### Threat Intel Service
**Responsibilities:**
- Periodic synchronization with darkapi.io
- Download and cache bad domain lists
- Download and cache bad IP lists
- Provide fast lookup for threat checking
- API key management and authentication

#### Baseline Scanner Service
**Responsibilities:**
- Comprehensive application inventory
- Missing patch detection
- Vulnerability assessment
- Exploitability scoring
- Initial baseline establishment

#### Network Monitor Service
**Responsibilities:**
- DNS enforcement (custom or cache0{1,2,3,4}.dnsscience.io)
- ICMP (ping/traceroute) control
- IP fragmentation detection
- Public IP exposure tracking

#### Report Generator Service
**Responsibilities:**
- Compliance report generation
- Missing patch summaries
- Public IP exposure analysis
- OS/Windows patch status
- Scheduled report delivery

### Platform Abstraction (internal/platform/)

**Responsibilities:**
- OS-specific implementations for all platforms
- Unified interface for daemon services
- Platform-specific optimizations
- Error handling and recovery

**Platform-Specific Implementations:**

**macOS:**
- Use `softwareupdate` for patch management
- Parse system_profiler for application inventory
- Leverage networksetup for DNS configuration
- Use pfctl for firewall rules

**Windows:**
- WMI queries for system information
- Windows Update API for patch management
- Registry parsing for application inventory
- PowerShell for network configuration
- Windows Firewall API

**Linux (Debian/Ubuntu):**
- apt/dpkg for package management
- unattended-upgrades integration
- dpkg -l for application inventory
- systemd-resolved or /etc/resolv.conf for DNS

**Linux (RHEL/Rocky):**
- yum/dnf for package management
- yum-security for security updates
- rpm -qa for application inventory
- NetworkManager or /etc/resolv.conf for DNS

### Storage Layer (internal/storage/)

**Responsibilities:**
- Persistent storage of scan results, configurations, and state
- In-memory caching for performance
- Audit logging for compliance
- JSON structure management
- Atomic writes for data integrity

**Storage Strategy:**
- Primary: Structured JSON files with indexing
- Cache: In-memory for frequently accessed data
- Audit: Append-only log for all changes
- Backup: Periodic snapshots with rotation

### IPC Layer (internal/ipc/)

**Responsibilities:**
- Secure communication between daemon and CLIs
- Authentication and authorization
- Request/response handling
- Streaming for large datasets

**IPC Mechanisms:**
- **Unix/Linux/macOS**: Unix domain sockets with file permissions
- **Windows**: Named pipes with ACLs
- **Protocol**: gRPC for structured communication
- **Auth**: Token-based with file-based credentials

## Data Flow

### 1. Daemon Initialization
```
main()
  → LoadConfig()
  → InitializePlatform()
  → InitializeStorage()
  → InitializeServices()
  → StartIPCServer()
  → RunEventLoop()
```

### 2. Patch Compliance Check
```
Scheduler Tick
  → PatchMonitor.ScanNow()
  → Platform.ListAvailablePatches()
  → Classifier.DetermineUrgency()
  → Storage.SaveScanResults()
  → CheckCompliance()
  → [Optional] TriggerAlerts()
```

### 3. Threat Intel Sync
```
Scheduler Tick
  → ThreatIntelService.SyncNow()
  → DarkAPIClient.GetBadDomains()
  → DarkAPIClient.GetBadIPs()
  → Storage.SaveThreatIntel()
  → UpdateCache()
```

### 4. CLI Request Flow
```
CLI Command
  → IPC.Connect()
  → IPC.Authenticate()
  → IPC.SendRequest()
  → Daemon.HandleRequest()
  → Service.Execute()
  → IPC.SendResponse()
  → CLI.DisplayResult()
```

### 5. Report Generation
```
ReportService.Generate()
  → Storage.LoadScanResults()
  → Storage.LoadThreatIntel()
  → Platform.GetSystemInfo()
  → Formatter.CreateReport()
  → Storage.SaveReport()
  → [Optional] API.UploadReport()
```

## Cross-Platform Considerations

### Build Strategy
- Use Go build tags for platform-specific code
- Separate files: `patches_darwin.go`, `patches_windows.go`, `patches_linux.go`
- Common interface in `patches.go`
- Platform detection at runtime for Linux distributions

### Privilege Requirements
- **macOS**: Run as root or with elevated privileges for system changes
- **Windows**: Require Administrator rights
- **Linux**: Run as root or use sudo for system operations

### Service Installation
- **macOS**: launchd plist in /Library/LaunchDaemons/
- **Windows**: Windows Service using golang.org/x/sys/windows/svc
- **Linux**: systemd unit file in /etc/systemd/system/

### File Locations
```
macOS:
  Config: /etc/afterdark/darkd.yaml
  Data: /var/lib/afterdark/
  Logs: /var/log/afterdark/
  Socket: /var/run/afterdark/darkd.sock

Windows:
  Config: C:\ProgramData\AfterDark\darkd.yaml
  Data: C:\ProgramData\AfterDark\data\
  Logs: C:\ProgramData\AfterDark\logs\
  Pipe: \\.\pipe\afterdark-darkd

Linux:
  Config: /etc/afterdark/darkd.yaml
  Data: /var/lib/afterdark/
  Logs: /var/log/afterdark/
  Socket: /var/run/afterdark/darkd.sock
```

## Security Considerations

### API Communication
- All external API calls over HTTPS/TLS 1.3+
- Certificate pinning for critical endpoints
- API key rotation support
- Rate limiting to prevent abuse
- Retry with exponential backoff

### Local Security
- IPC authentication tokens stored in secure locations
- File permissions: 600 for configs, 700 for data directories
- Audit logging of all privileged operations
- Input validation on all API inputs
- Protection against path traversal attacks

### Data Protection
- Sensitive data encrypted at rest (API keys, credentials)
- Secure key derivation (PBKDF2 or similar)
- No plaintext passwords in logs or storage
- Memory zeroing for sensitive data
- Regular security audits

## Performance Targets

### Resource Usage
- Memory: < 100MB RSS under normal load
- CPU: < 5% average, < 20% during scans
- Disk I/O: Minimal, batch writes
- Network: < 10MB/day for threat intel sync

### Response Times
- CLI commands: < 100ms for status queries
- Patch scan: < 30 seconds for full system scan
- Threat intel sync: < 5 seconds for typical update
- Report generation: < 10 seconds for standard report

### Scalability
- Support 10,000+ applications in inventory
- Handle 1,000+ patches in tracking
- Store 1 year of scan history
- 100+ concurrent CLI connections

## Monitoring and Observability

### Metrics
- Service health status
- Scan duration and frequency
- Patch compliance percentage
- Threat intel cache hit rate
- API call success/failure rates
- Storage size and growth rate

### Logging
- Structured JSON logging
- Log levels: DEBUG, INFO, WARN, ERROR, FATAL
- Log rotation (size and time-based)
- Integration with syslog/Windows Event Log
- Optional remote logging to aeims.app/OCI observability

### Health Checks
- HTTP endpoint for external monitoring
- Service-level health checks
- Storage availability checks
- API connectivity checks
- Last successful scan timestamp

## Configuration Management

### Configuration File (YAML)
```yaml
daemon:
  log_level: info
  data_dir: /var/lib/afterdark
  pid_file: /var/run/afterdark/darkd.pid

api:
  afterdark:
    url: https://api.afterdarksys.com
    timeout: 30s
  darkapi:
    url: https://api.darkapi.io
    api_key: ${DARKAPI_API_KEY}
    timeout: 30s
  dnsscience:
    url: https://api.dnsscience.io
    timeout: 10s

services:
  patch_monitor:
    enabled: true
    scan_interval: 1h
    auto_install_windows: true
    urgency_tiers:
      critical: 1d
      kernel_network: 2d
      software: 3d
      windows_standard: 7d

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
  backup_retention: 30d

ipc:
  socket_path: /var/run/afterdark/darkd.sock
  auth_enabled: true
  auth_token_file: /var/lib/afterdark/.auth_token
```

### Environment Variables
- `DARKAPI_API_KEY`: API key for darkapi.io
- `AFTERDARK_CONFIG`: Override config file path
- `AFTERDARK_LOG_LEVEL`: Override log level
- `AFTERDARK_DATA_DIR`: Override data directory

## Error Handling Strategy

### Error Categories
1. **Transient Errors**: Network timeouts, temporary API failures → Retry with backoff
2. **Configuration Errors**: Invalid config → Fail fast at startup
3. **Platform Errors**: Unsupported OS operations → Graceful degradation
4. **Storage Errors**: Disk full, permissions → Alert and attempt recovery
5. **Service Errors**: Individual service failures → Continue other services

### Recovery Strategies
- Automatic retry for transient failures
- Circuit breaker for failing external APIs
- Fallback to cached data when APIs unavailable
- Graceful degradation of non-critical features
- Clear error messages with remediation steps

## Testing Strategy

### Unit Tests
- Test all business logic in isolation
- Mock external dependencies (APIs, storage, platform)
- Achieve > 80% code coverage
- Table-driven tests for complex logic

### Integration Tests
- Test service interactions
- Use test fixtures for API responses
- Test storage operations with temporary directories
- Validate configuration loading

### Platform Tests
- Test platform-specific implementations on actual OS
- Use VMs or containers for cross-platform validation
- Automated testing in CI/CD pipeline

### End-to-End Tests
- Full daemon lifecycle tests
- CLI interaction scenarios
- Multi-service workflows
- Performance benchmarks

## Deployment Considerations

### Installation
- Platform-specific installers (pkg, msi, deb, rpm)
- Automated service registration
- Default configuration generation
- Permission setup
- Initial API key configuration wizard

### Upgrades
- Graceful shutdown of old version
- Data migration scripts
- Configuration compatibility checks
- Rollback capability
- Zero-downtime upgrades (future)

### Monitoring
- Integration with enterprise monitoring (Prometheus, Datadog)
- Custom metrics export
- Health check endpoints
- Log aggregation support

### Compliance
- Audit logging for SOC2/ISO27001
- Data retention policies
- Secure credential management
- Regular security updates
