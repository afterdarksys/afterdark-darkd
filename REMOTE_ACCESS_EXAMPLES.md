# Remote Access Mode Examples

This document demonstrates the behavior of the `--remote` flag with different modes.

## Overview

The `--remote` flag provides three levels of information disclosure control:

1. **Enabled** - Full information (default, trusted access)
2. **Disabled** - Minimal information with error messages
3. **Restricted** - No information leakage (returns only "Status: Restricted")

## Use Cases

### Enabled (Default - Full Access)

Use for local, trusted access where full system information is needed.

```bash
$ afterdark-darkd status
AfterDark-DarkD Status
======================
Remote Access: Enabled

● Daemon: running (PID: 1234)
  Version: v1.0.0
  Commit:  abc123
  Built:   2026-01-25

Configuration
  File: /etc/afterdark/darkd.yaml
  Exists: yes

System Identity
  System ID: sys_abc123xyz789
  Hostname:  production-server-01
  OS/Arch:   linux/amd64
  Status:    registered (admin@company.com)

Commands:
  afterdark-darkd start     - Start the daemon
  afterdark-darkd stop      - Stop the daemon
  afterdark-darkd restart   - Restart the daemon
  afterdark-darkd logs -f   - Follow daemon logs
```

### Disabled (Access Denied with Context)

Use for scenarios where you want to clearly deny access but provide context.

```bash
$ afterdark-darkd --remote Disabled status
Remote access: Disabled
Local status information is unavailable in remote mode

$ afterdark-darkd --remote Disabled logs
Error: logs unavailable: remote access is disabled

$ afterdark-darkd --remote Disabled config show
Error: configuration unavailable: remote access is disabled
```

**When to use:**
- API endpoints where you want clear error messages
- Monitoring systems that need to know access was denied
- Debugging scenarios where context is helpful

### Restricted (Maximum Security - Zero Information Leakage)

Use when queried from untrusted sources or over the network. Prevents ANY information disclosure about the system state.

```bash
$ afterdark-darkd --remote Restricted status
Status: Restricted

$ afterdark-darkd --remote Restricted logs
Status: Restricted

$ afterdark-darkd --remote Restricted config show
Status: Restricted

$ afterdark-darkd --remote Restricted show machines
Status: Restricted
```

**When to use:**
- Remote monitoring from untrusted networks
- Public-facing endpoints
- Security compliance requirements
- Prevent information gathering/reconnaissance
- Situations where even knowing if daemon is running is sensitive

**Security benefit:** An attacker cannot determine:
- If the daemon is running
- System configuration
- Registered machines
- Any system details
- Whether the command even worked

## Real-World Scenarios

### Scenario 1: Monitoring from Untrusted Network

```bash
# On monitoring server (untrusted network)
ssh prod-server "afterdark-darkd --remote Restricted status"
# Output: Status: Restricted
# Attacker learns nothing useful

# On local server (trusted)
afterdark-darkd status
# Output: Full detailed information
```

### Scenario 2: API Endpoint

```python
# Flask API endpoint
@app.route('/daemon/status')
def daemon_status():
    # Use Disabled mode for clear error handling
    result = subprocess.run(
        ['afterdark-darkd', '--remote', 'Disabled', 'status'],
        capture_output=True, text=True
    )

    if result.returncode != 0:
        return {"error": "Remote access disabled"}, 403

    return {"status": result.stdout}, 200
```

### Scenario 3: Secure Remote Administration

```bash
#!/bin/bash
# secure-admin.sh - Only allow full access from specific IPs

TRUSTED_IPS="10.0.0.0/8 192.168.1.0/24"
CLIENT_IP=$(echo $SSH_CLIENT | awk '{print $1}')

if echo "$TRUSTED_IPS" | grep -q "$CLIENT_IP"; then
    # Trusted network - full access
    afterdark-darkd "$@"
else
    # Untrusted network - restricted
    afterdark-darkd --remote Restricted "$@"
fi
```

### Scenario 4: Configuration Management

```yaml
# Ansible playbook
- name: Check darkd status on production
  hosts: production
  tasks:
    - name: Safe status check
      command: afterdark-darkd --remote Restricted status
      register: status
      failed_when: false
      changed_when: false

    - name: Report (no sensitive data leaked)
      debug:
        msg: "{{ status.stdout }}"
```

## Security Comparison

| Scenario | Enabled | Disabled | Restricted |
|----------|---------|----------|------------|
| Shows daemon running? | ✅ Yes | ❌ No | ❌ No |
| Shows PID? | ✅ Yes | ❌ No | ❌ No |
| Shows system ID? | ✅ Yes | ❌ No | ❌ No |
| Shows configuration? | ✅ Yes | ❌ No | ❌ No |
| Shows registration status? | ✅ Yes | ❌ No | ❌ No |
| Error messages? | ✅ Detailed | ⚠️ Generic | ❌ None |
| Indicates access denied? | N/A | ✅ Yes | ❌ No |
| Information leakage | 🔴 Full | 🟡 Minimal | 🟢 Zero |

## Command Reference

### Status Command Outputs

```bash
# Enabled
$ afterdark-darkd status
# Full detailed status with all information

# Disabled
$ afterdark-darkd --remote Disabled status
# Remote access: Disabled
# Local status information is unavailable in remote mode

# Restricted
$ afterdark-darkd --remote Restricted status
# Status: Restricted
```

### Logs Command Outputs

```bash
# Enabled
$ afterdark-darkd logs
# Shows log content

# Disabled
$ afterdark-darkd --remote Disabled logs
# Error: logs unavailable: remote access is disabled

# Restricted
$ afterdark-darkd --remote Restricted logs
# Status: Restricted
```

### Config Command Outputs

```bash
# Enabled
$ afterdark-darkd config show
# Shows full configuration file

# Disabled
$ afterdark-darkd --remote Disabled config show
# Error: configuration unavailable: remote access is disabled

# Restricted
$ afterdark-darkd --remote Restricted config show
# Status: Restricted
```

## Implementation Notes

### Validation

The remote access mode is validated at startup:

```bash
$ afterdark-darkd --remote Invalid status
Error: invalid remote access mode: Invalid (must be Enabled, Disabled, or Restricted)
```

### Default Behavior

If `--remote` is not specified, defaults to `Enabled`:

```bash
$ afterdark-darkd status
# Same as: afterdark-darkd --remote Enabled status
```

### Environment Variable Support

You can set the mode via environment variable (if implemented):

```bash
export DARKD_REMOTE_MODE=Restricted
afterdark-darkd status
# Runs in Restricted mode
```

## Best Practices

1. **Always use Restricted for untrusted networks**
   ```bash
   ssh remote "afterdark-darkd --remote Restricted status"
   ```

2. **Use Disabled for internal APIs** (clear errors for debugging)
   ```bash
   curl http://internal-api/daemon/status  # Uses --remote Disabled
   ```

3. **Use Enabled (default) only locally or over VPN**
   ```bash
   # On local machine or trusted VPN
   afterdark-darkd status
   ```

4. **Wrapper scripts should enforce restrictions**
   ```bash
   #!/bin/bash
   # Only allow Restricted mode in this wrapper
   afterdark-darkd --remote Restricted "$@"
   ```

5. **Audit logs should record remote access mode**
   ```
   2026-01-25 10:30:45 INFO status command executed (remote=Restricted, user=monitoring, ip=10.0.1.50)
   ```

## Security Benefits

### Prevents Information Disclosure

- Attackers cannot determine if daemon is running
- System fingerprinting prevented
- Configuration details protected
- No version information leaked

### Compliance

- Meets zero-trust security requirements
- Supports least-privilege access models
- Enables granular access control
- Audit trail friendly

### Defense in Depth

- Works alongside firewall rules
- Complements network segmentation
- Independent of SSH/TLS configuration
- Application-level security control
