# AfterDark-DarkD CLI Reference

Complete command-line reference for the AfterDark endpoint security daemon.

## Table of Contents

- [Global Flags](#global-flags)
- [Daemon Management](#daemon-management)
- [Service Management](#service-management)
- [Configuration](#configuration)
- [Monitoring](#monitoring)
- [System Identity](#system-identity)
- [API Server](#api-server)
- [Resource Management](#resource-management)

## Global Flags

Available for all commands:

```bash
-c, --config string      Config file path (default: /etc/afterdark/darkd.yaml)
-l, --log-level string   Log level: debug, info, warn, error (default: info)
--remote string          Remote access mode: Enabled, Disabled, Restricted (default: Enabled)
--version                Show version information
--help                   Show help
```

### Remote Access Modes

The `--remote` flag controls information disclosure when commands are executed remotely:

- **`Enabled`** (default): Full status and information disclosure
- **`Disabled`**: Denies access with error message, minimal information
- **`Restricted`**: Returns only "Status: Restricted" - no information leakage

**Security Note:** When using `Restricted` mode, commands that would normally return sensitive information (status, logs, config, machine info) will only return "Status: Restricted" without leaking any details about the daemon state, configuration, or whether it's running.

**Example usage:**
```bash
# Remote query with restricted mode (safe for untrusted networks)
afterdark-darkd --remote Restricted status
# Output: Status: Restricted

# Remote query with disabled mode
afterdark-darkd --remote Disabled status
# Output: Remote access: Disabled
#         Local status information is unavailable in remote mode

# Full local access (default)
afterdark-darkd status
# Output: Full detailed status information
```

## Daemon Management

### Start/Run Commands

#### `run` / `daemonize`
Start the daemon in background mode.

```bash
afterdark-darkd run
afterdark-darkd daemonize
```

Both commands are aliases and do the same thing.

#### `foreground`
Run the daemon in foreground mode with console output.

```bash
afterdark-darkd foreground
```

Useful for:
- Container deployments (Docker/Kubernetes)
- Debugging
- Development
- Direct supervision

#### `debug`
Run in debug mode with verbose logging.

```bash
afterdark-darkd debug
```

Equivalent to `foreground` with `--log-level=debug`.

### Control Commands

#### `stop`
Stop the running daemon gracefully.

```bash
afterdark-darkd stop
```

Sends SIGTERM signal to the daemon process.

#### `restart`
Restart the daemon.

```bash
afterdark-darkd restart
```

Stops the daemon if running, then starts it again.

#### `status`
Show daemon status and system information.

```bash
afterdark-darkd status
afterdark-darkd status --verbose
```

**Output includes:**
- Daemon running status (PID)
- Version information
- Configuration file status
- System identity
- Registration status
- Service installation status (with --verbose)

**Example output:**
```
AfterDark-DarkD Status
======================

● Daemon: running (PID: 1234)
  Version: v1.0.0
  Commit:  abc123
  Built:   2026-01-25

Configuration
  File: /etc/afterdark/darkd.yaml
  Exists: yes

System Identity
  System ID: sys_abc123xyz789
  Hostname:  macbook-pro.local
  OS/Arch:   darwin/arm64
  Status:    registered (user@example.com)
```

## Service Management

Manage systemd (Linux) or launchd (macOS) services.

#### `service install`
Install system service.

```bash
sudo afterdark-darkd service install
```

Creates:
- **Linux**: `/etc/systemd/system/afterdark-darkd.service`
- **macOS**: `/Library/LaunchDaemons/com.afterdark.darkd.plist`

#### `service uninstall`
Remove system service.

```bash
sudo afterdark-darkd service uninstall
```

#### `service enable`
Enable auto-start on boot and start the service.

```bash
sudo afterdark-darkd service enable
```

#### `service disable`
Disable auto-start and stop the service.

```bash
sudo afterdark-darkd service disable
```

### Service Management Examples

```bash
# Complete installation workflow
sudo afterdark-darkd service install
sudo afterdark-darkd service enable

# Check status
afterdark-darkd status

# View logs
afterdark-darkd logs -f

# Disable and remove
sudo afterdark-darkd service disable
sudo afterdark-darkd service uninstall
```

## Configuration

#### `config show`
Display current configuration.

```bash
afterdark-darkd config show
```

#### `config path`
Show configuration file path.

```bash
afterdark-darkd config path
```

#### `config validate`
Validate configuration file syntax.

```bash
afterdark-darkd config validate
```

## Monitoring

#### `logs`
View daemon logs.

```bash
afterdark-darkd logs
afterdark-darkd logs -f
afterdark-darkd logs -n 100
afterdark-darkd logs --follow --lines 50
```

**Flags:**
- `-f, --follow`: Follow log output (like `tail -f`)
- `-n, --lines int`: Number of lines to show (default: 50)

**Log file location:** `/var/log/afterdark/darkd.log`

## System Identity

#### `generate-system-id`
Generate or regenerate system identifier.

```bash
afterdark-darkd generate-system-id
afterdark-darkd generate-system-id --force
```

**Flags:**
- `-f, --force`: Force regeneration if ID already exists

The system ID is:
- Derived from machine ID and hostname
- Persistent across reboots
- Required for registration
- Stored in `/etc/afterdark/identity.json` (or `~/.config/afterdark/identity.json`)

**Example output:**
```
System ID generated successfully!

  System ID:  sys_7a8b9c0d1e2f3g4h
  Hostname:   macbook-pro.local
  Machine ID: abc123-def456-ghi789
  OS/Arch:    darwin/arm64

Next steps:
  1. Run 'darkdadm login' to authenticate with your AfterDark account
  2. The system will be registered to your account automatically
```

## API Server

#### `api start`
Start API server only (without full daemon services).

```bash
afterdark-darkd api start
```

Note: API-only mode is planned but not yet fully implemented.

## Resource Management

### `show` Commands

Display information about managed resources.

#### `show machines`
List registered machines.

```bash
afterdark-darkd show machines
```

#### `show files`
List tracked files.

```bash
afterdark-darkd show files
```

#### `show file [path]`
Show details for a specific file.

```bash
afterdark-darkd show file /path/to/file
```

#### `show collection [name]`
List or show details of collections.

```bash
# List all collections
afterdark-darkd show collection

# Show specific collection
afterdark-darkd show collection downloads
```

**Built-in collections:**
- `default` - Default collection
- `downloads` - Downloaded files
- `documents` - Document files

## Security Considerations

### Remote Access Control

Use the `--remote` flag to control information disclosure when executing commands over the network or from untrusted contexts:

```bash
# Query from untrusted source - no information leakage
ssh remote-host "afterdark-darkd --remote Restricted status"
# Returns: Status: Restricted

# Query with access denied
afterdark-darkd --remote Disabled logs
# Returns: Error - remote access is disabled

# Full access (trusted/local only)
afterdark-darkd status
# Returns: Full system information
```

**Commands affected by remote access mode:**
- `status` - System and daemon status
- `logs` - Log file viewing
- `config show` - Configuration viewing
- `show machines` - Machine information
- `show files` - File tracking information

**Commands NOT affected:**
- `run`, `start`, `stop`, `restart` - Daemon control (always local)
- `service` - Service installation (requires sudo)
- `generate-system-id` - Identity generation

### Best Practices

1. **Use `Restricted` for remote monitoring** - Prevents information disclosure
2. **Use `Disabled` for API endpoints** - Clear error messages without data leakage
3. **Use `Enabled` (default) for local/trusted access** - Full functionality
4. **Set via configuration** - Can be configured in daemon config for consistent behavior

## Common Workflows

### Initial Setup

```bash
# 1. Generate system ID
sudo afterdark-darkd generate-system-id

# 2. Validate configuration
afterdark-darkd config validate

# 3. Start daemon
sudo afterdark-darkd run
```

### Production Deployment

```bash
# 1. Install as system service
sudo afterdark-darkd service install

# 2. Enable auto-start
sudo afterdark-darkd service enable

# 3. Verify running
afterdark-darkd status

# 4. Monitor logs
afterdark-darkd logs -f
```

### Troubleshooting

```bash
# Check status
afterdark-darkd status --verbose

# View recent logs
afterdark-darkd logs -n 100

# Validate configuration
afterdark-darkd config validate

# Run in debug mode
sudo afterdark-darkd debug

# Restart service
sudo afterdark-darkd restart
```

### Container Deployment

```bash
# Run in foreground (for Docker/K8s)
afterdark-darkd foreground --config /etc/darkd/config.yaml
```

## Exit Codes

- `0` - Success
- `1` - General error
- `2` - Configuration error
- `3` - Daemon already running
- `4` - Daemon not running

## Environment Variables

- `DARKD_CONFIG` - Override config file path
- `DARKD_LOG_LEVEL` - Override log level
- `DARKD_LOG_FORMAT` - Log format (json, console)

## Files and Directories

### Configuration
- `/etc/afterdark/darkd.yaml` - Main configuration file

### Runtime
- `/var/run/afterdark/darkd.pid` - PID file
- `/var/log/afterdark/darkd.log` - Log file

### Data
- `/var/lib/afterdark/` - Data directory
- `/etc/afterdark/identity.json` - System identity

### Service Files
- `/etc/systemd/system/afterdark-darkd.service` - Systemd unit (Linux)
- `/Library/LaunchDaemons/com.afterdark.darkd.plist` - Launchd plist (macOS)

## Version Information

```bash
afterdark-darkd --version
```

Shows:
- Version number
- Git commit hash
- Build timestamp

## Tips

1. **Always use sudo** for daemon operations that require system access
2. **Check status first** before starting/stopping
3. **Follow logs** when troubleshooting: `afterdark-darkd logs -f`
4. **Validate config** before restarting: `afterdark-darkd config validate`
5. **Use debug mode** for detailed troubleshooting: `afterdark-darkd debug`

## See Also

- `darkdadm` - Administrative tool for user management
- `darkd-config` - Configuration management utility
- Main documentation: `/usr/share/doc/afterdark-darkd/README.md`
