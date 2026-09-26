# Stopping and Upgrading darkd (Signed Control Tokens)

On macOS, darkd's Endpoint Security self-protection denies:

- terminating or stopping signals sent to darkd by any process other than
  launchd, the kernel, or darkd itself, and
- `launchctl stop|kickstart|unload|bootout|disable|remove|kill`, `kill`,
  `pkill`, and `killall` when an argument names darkd exactly
  (`com.afterdarksys.darkd`, `com.afterdark.darkd`, their `.plist` files,
  `afterdark-darkd`). Sibling components such as
  `com.afterdarksys.darkd.netguard` stay stoppable.

Root alone cannot stop it. The sanctioned path is a single-use token signed
offline with an Ed25519 key that the endpoint trusts. A verified token opens a
**120 second maintenance window** in which those stops are allowed.

| Token action | Effect |
|--------------|--------|
| `stop`       | darkd journals the event, opens the window, and shuts itself down cleanly. |
| `upgrade`    | darkd journals the event and opens the window; it keeps running so an installer can unload, replace, and reload it. |

With no trusted key installed, no token is accepted and darkd cannot be stopped
this way (fail closed).

## 1. Generate the signing key (offline)

On an offline or otherwise protected admin machine:

```bash
afterdark-darkdadm control keygen --out ~/darkd-control
# private key: ~/darkd-control/darkd-control.key  (0600; keep offline)
# public key:  ~/darkd-control/darkd-control.pub
```

`keygen` never overwrites existing files. `sign-stop` refuses a private key
readable by group or others.

## 2. Trust the public key on each endpoint

Install the public key, one base64 key per line (up to 16 keys; `#` comments
allowed), in a file that is **owned by root and not group- or world-writable**.
Its directory must meet the same rules. darkd rejects a file or directory that
is a symlink, is owned by another user, or is writable by group or others.

```bash
sudo install -o root -g wheel -m 0644 darkd-control.pub /etc/afterdark/control-stop-keys.pub
```

`/etc/afterdark/control-stop-keys.pub` is the default. To use another path, set
it in `darkd.yaml`:

```yaml
control:
  stop_public_keys_file: /etc/afterdark/control-stop-keys.pub
```

The file is read on every token presentation, so adding or revoking a key
needs no restart.

With Ansible, set `darkd_control_public_keys` (a list of base64 keys); the macOS
tasks install it with those permissions.

## 3. Sign a token (offline)

A token is bound to one endpoint's system ID. Read it on the endpoint with
`sudo -H afterdark-darkd status` (the "System ID" line), then sign on the admin
machine:

```bash
afterdark-darkdadm control sign-stop \
  --key ~/darkd-control/darkd-control.key \
  --system-id <system id> \
  --action upgrade \
  --ttl 10m > upgrade.token
```

Rules darkd enforces:

- lifetime (`--ttl`) at most 15 minutes;
- rejected once `not_after` has passed, or if `issued_at` is more than 5
  minutes ahead of the endpoint's clock;
- each token works once. Used nonces are stored in
  `<storage.path>/control-nonces.json` (0600) and survive restarts;
- tokens larger than 4 KiB, altered in any byte, or signed by an untrusted key
  are rejected.

Treat an unexpired token like a password: anyone who presents it first uses it.

## 4. Present the token and stop or upgrade

Run as root on the endpoint. The IPC call also requires the local IPC bearer
token (`--token-file`, default `/var/lib/afterdark/.auth_token`).

Stop darkd:

```bash
sudo afterdark-darkdadm stop --token stop.token
```

Upgrade darkd (within 120 seconds of the `stop` command):

```bash
sudo afterdark-darkdadm stop --token upgrade.token
sudo launchctl unload /Library/LaunchDaemons/com.afterdarksys.darkd.plist
sudo install -o root -g wheel -m 0755 afterdark-darkd /usr/local/bin/afterdark-darkd
sudo launchctl load /Library/LaunchDaemons/com.afterdarksys.darkd.plist
```

`--token -` reads the token from stdin.

The daemon's own service commands take the token directly and fail with
instructions when none is given:

```bash
sudo afterdark-darkd service disable --control-token upgrade.token
sudo afterdark-darkd service uninstall --control-token upgrade.token
```

### Ansible

`playbooks/deploy.yml` restarts macOS hosts through
`tasks/macos_restart.yml`: it copies the per-host token from the
`darkd_upgrade_token` host variable to `/var/run/afterdark/darkd-upgrade.token`
(0600), runs `afterdark-darkdadm stop --token ...`, runs
`launchctl kickstart -k system/com.afterdarksys.darkd`, and always removes the
token file. Token tasks run with `no_log`. Sign one `upgrade` token per host just
before the run, for example into a vaulted `host_vars/<host>.yml`.

## Audit

Every presentation is journaled as event type `agent.control` with facts
`control.outcome` (`accepted` or `denied`), `control.peer_uid`, and for accepted
tokens `control.action`, `control.key_fingerprint` (SHA-256 of the public key),
`control.nonce_sha256`, `control.not_after`, and `control.window_seconds`. The
raw token and nonce are never logged or journaled. If the acceptance event
cannot be written, the window is not opened and the token is spent.

## Requirements and limits

- The IPC peer must be uid 0 on the local Unix socket; TCP IPC cannot present
  tokens.
- While the window is open, any process may stop darkd; the window is not tied
  to the presenting peer.
- A stolen private key, or root rewriting the trusted key file, defeats this
  control. Keep the private key offline.
- Hosts running a darkd build without `ControlService` answer `Unimplemented`;
  upgrade those once by the previous procedure.
