# AfterDark macOS Security Plugin

Comprehensive macOS security auditing and monitoring plugin for afterdark-darkd.

## Features

### Directory Services Auditing
- Enumerate all local users and groups
- Detect hidden admin accounts
- Identify privilege escalations
- Monitor for new user creation
- Track admin group membership changes

### Keychain Analysis
- List keychain items (metadata only by default)
- Detect duplicate credentials
- Find expired certificates
- Identify weak cryptography
- Search for suspicious entries
- Track keychain changes over time

### File System Monitoring
- Monitor Directory Services database changes
- Track keychain file modifications
- Watch launch daemons and agents
- Monitor system extensions
- Track SSH configuration changes
- Monitor sudoers and PAM configuration

### Security Snapshots
- Point-in-time security state capture
- Compare snapshots for change detection
- Historical analysis
- Automatic periodic snapshots

### User Authorization
- Tiered authorization levels
- User consent for sensitive operations
- Admin privilege elevation
- Automatic expiration

## Installation

### Build from source
```bash
cd plugins/osx-security
make build
```

### Install as plugin
```bash
# System-wide (requires root)
make install

# User-local
make install-local
```

## Usage

### As a darkd Plugin

The plugin integrates with afterdark-darkd via gRPC. Configure in `darkd.yaml`:

```yaml
plugins:
  osx-security:
    auto_snapshot: true
    snapshot_interval_minutes: 60
    monitor:
      directory_services: true
      keychain: true
```

### Standalone Mode

Run directly from command line:

```bash
# Directory Services audit
./osx-security ds_audit

# Get admin users
./osx-security ds_get_admins

# Keychain analysis
./osx-security keychain_analyze

# Take security snapshot
./osx-security snapshot_take

# Compare snapshots
./osx-security snapshot_compare older=abc123 newer=def456

# Full security audit
./osx-security full_audit
```

## Authorization Levels

| Level | Name | Capabilities |
|-------|------|--------------|
| 0 | Basic | Read-only system info, DS auditing |
| 1 | Enhanced | Keychain metadata, monitoring, snapshots |
| 2 | Full Access | Read keychain secrets (requires user auth) |
| 3 | Admin | System modifications (requires root) |

## Actions Reference

### Directory Services
- `ds_audit` - Full Directory Services audit
- `ds_get_user` - Get specific user (username=<name>)
- `ds_get_admins` - List all admin users
- `ds_get_hidden` - List hidden non-system users

### Keychain
- `keychain_analyze` - Analyze keychain security
- `keychain_search` - Search items (query=<term>)
- `keychain_duplicates` - Find duplicates

### Snapshots
- `snapshot_take` - Take new snapshot
- `snapshot_list` - List available snapshots
- `snapshot_compare` - Compare two snapshots
- `snapshot_diff_latest` - Diff current vs latest

### Monitoring
- `monitor_status` - Get monitor status
- `monitor_events` - Get recent events

### Authorization
- `auth_status` - Show authorization status
- `auth_elevate` - Request elevated access
- `auth_revoke` - Revoke elevated access

### Combined
- `full_audit` - Run comprehensive audit
- `status` - Show plugin status

## Security Findings

The plugin detects various security issues:

| Severity | Type | Description |
|----------|------|-------------|
| Critical | hidden_admin | Hidden account with admin privileges |
| Critical | privilege_escalation | User granted admin privileges |
| High | suspicious_uid | Admin with low UID |
| High | phantom_admin | Admin group member not in users |
| Medium | new_user | New user account created |
| Medium | hidden_interactive | Hidden user with shell |

## Architecture

```
osx-security/
├── main.go           # Plugin entry point, ServicePlugin interface
├── dsaudit/          # Directory Services auditing
├── keywatch/         # Keychain analysis
├── fsmonitor/        # File system monitoring
├── snapshot/         # State snapshotting
├── auth/             # User authorization
├── Makefile          # Build utilities
└── README.md         # Documentation
```

## EDR Integration

When running as a darkd plugin, the following capabilities are available:

- **Threat Correlation**: Security findings are correlated with other darkd threat data
- **Centralized Logging**: All events logged to darkd's unified logging
- **Alerting**: Findings trigger darkd alerts based on severity
- **API Access**: All actions available via darkd REST/gRPC APIs
- **Automation**: Can be triggered by darkd automation rules

## Development

```bash
# Run tests
make test

# Run with coverage
make test-coverage

# Format code
make fmt

# Lint
make lint
```

## License

MIT License - After Dark Systems, LLC
