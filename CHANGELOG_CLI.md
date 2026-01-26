# CLI Enhancements Changelog

## 2026-01-25 - Enhanced Cobra CLI

### New Security Feature: Remote Access Control

Added `--remote` global flag for controlling information disclosure:

- **`--remote Enabled`** (default) - Full information disclosure
- **`--remote Disabled`** - Minimal information with error messages
- **`--remote Restricted`** - Zero information leakage (returns only "Status: Restricted")

**Security Impact:**
- Prevents reconnaissance when queried from untrusted sources
- No information about daemon state, configuration, or system details
- Complies with zero-trust security models
- Application-level security independent of network controls

**Affected Commands:**
- `status` - System and daemon status
- `logs` - Log file viewing
- `config show` - Configuration viewing
- `show machines` - Machine information
- `show files` - File tracking information

**Usage Example:**
```bash
# Remote/untrusted query - zero information leakage
afterdark-darkd --remote Restricted status
# Output: Status: Restricted

# Local/trusted query - full information
afterdark-darkd status
# Output: Full detailed status
```

See `REMOTE_ACCESS_EXAMPLES.md` for detailed usage scenarios.

### New Commands Added

#### Daemon Control
- **`stop`** - Stop the running daemon gracefully (SIGTERM)
- **`restart`** - Stop and restart the daemon
- **`logs`** - View daemon logs with options:
  - `-f, --follow` - Follow log output (tail -f)
  - `-n, --lines` - Number of lines to show

#### Configuration Management
- **`config`** - Configuration management command group:
  - `config show` - Display current configuration
  - `config path` - Show configuration file path
  - `config validate` - Validate configuration syntax

#### Service Management
- **`service`** - System service management command group:
  - `service install` - Install systemd/launchd service
  - `service uninstall` - Remove system service
  - `service enable` - Enable auto-start on boot
  - `service disable` - Disable auto-start

### Enhanced Commands

#### `status`
Improved with:
- Color-coded output (green=running, red=stopped, yellow=warning)
- Detailed system information display
- Configuration file status
- System identity information
- Registration status
- Service installation status (with --verbose flag)
- Helpful command suggestions

### Cross-Platform Support

All commands now support both:
- **Linux** (systemd)
- **macOS** (launchd)

Service management automatically detects the platform and uses the appropriate service manager.

### New Features

1. **Graceful Shutdown** - `stop` command sends SIGTERM for clean shutdown
2. **Log Following** - Real-time log monitoring with `logs -f`
3. **Service Installation** - One-command service setup across platforms
4. **Enhanced Status** - Beautiful, informative status output
5. **Config Validation** - Pre-flight checks before daemon start

### Dependencies

Already using:
- `github.com/spf13/cobra` - CLI framework
- `github.com/spf13/pflag` - POSIX flag parsing (via Cobra)
- `github.com/inconshreveable/mousetrap` - Windows CLI support (via Cobra)

### Files Modified

- `cmd/afterdark-darkd/main.go` - Added new commands and enhanced existing ones

### Files Created

- `CLI_REFERENCE.md` - Comprehensive CLI documentation
- `CHANGELOG_CLI.md` - This changelog

## Usage Examples

### Start and manage daemon
```bash
# Start daemon
sudo afterdark-darkd run

# Check status
afterdark-darkd status

# View logs
afterdark-darkd logs -f

# Stop daemon
sudo afterdark-darkd stop

# Restart daemon
sudo afterdark-darkd restart
```

### Install as system service
```bash
# Install service
sudo afterdark-darkd service install

# Enable auto-start
sudo afterdark-darkd service enable

# Check status
afterdark-darkd status --verbose
```

### Configuration management
```bash
# Show config
afterdark-darkd config show

# Validate config
afterdark-darkd config validate

# Show config path
afterdark-darkd config path
```

## Breaking Changes

None - all changes are backward compatible additions.

## Migration Notes

Existing deployments can continue using:
- `afterdark-darkd run` - Still works
- `afterdark-darkd daemonize` - Still works
- `afterdark-darkd foreground` - Still works
- `afterdark-darkd debug` - Still works

New commands are purely additive.

## Platform Compatibility

| Command | Linux | macOS | Windows |
|---------|-------|-------|---------|
| run/daemonize | ✅ | ✅ | ✅ |
| stop | ✅ | ✅ | ✅ |
| restart | ✅ | ✅ | ✅ |
| status | ✅ | ✅ | ✅ |
| logs | ✅ | ✅ | ⚠️ (requires tail) |
| config | ✅ | ✅ | ✅ |
| service install | ✅ (systemd) | ✅ (launchd) | ❌ |
| service enable | ✅ (systemd) | ✅ (launchd) | ❌ |

Windows service management would require additional work with Windows Service Manager.

## Future Enhancements

Potential additions:
- [ ] `reload` - Reload configuration without restart (SIGHUP)
- [ ] `test` - Test configuration and connectivity
- [ ] `backup` - Backup configuration and data
- [ ] `restore` - Restore from backup
- [ ] `health` - Health check endpoint
- [ ] `metrics` - Show runtime metrics
- [ ] Windows service support
- [ ] Shell completion generation (bash, zsh, fish)
