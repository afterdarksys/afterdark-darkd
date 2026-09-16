// Package endpointreport produces bounded, read-only host observations.
package endpointreport

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

type Sensor struct {
	Sensor        string         `json:"sensor"`
	State         string         `json:"state"`
	ObservedAt    string         `json:"observed_at"`
	LastSuccessAt string         `json:"last_success_at,omitempty"`
	Collected     *int64         `json:"collected,omitempty"`
	Dropped       *int64         `json:"dropped,omitempty"`
	Errors        *int64         `json:"errors,omitempty"`
	Reason        string         `json:"reason,omitempty"`
	RuleVersion   string         `json:"rule_version,omitempty"`
	Details       map[string]any `json:"details,omitempty"`
}
type Observation struct {
	Type     string
	Category string
	Data     map[string]any
	Facts    map[string]any
	Entities map[string]any
}
type Runner func(context.Context, string, ...string) ([]byte, error)

type limitedBuffer struct {
	b   []byte
	max int
}

func (b *limitedBuffer) Write(p []byte) (int, error) {
	if len(b.b)+len(p) > b.max {
		return 0, fmt.Errorf("collector output exceeds limit")
	}
	b.b = append(b.b, p...)
	return len(p), nil
}
func Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	output := &limitedBuffer{max: 8 * 1024}
	cmd.Stdout = output
	cmd.Stderr = output
	err := cmd.Run()
	if ctx.Err() != nil {
		err = ctx.Err()
	}
	return output.b, err
}
func State(err error, output []byte) string {
	if err == nil {
		return "running"
	}
	if errors.Is(err, exec.ErrNotFound) || errors.Is(err, os.ErrNotExist) {
		return "unsupported"
	}
	lower := strings.ToLower(string(output) + err.Error())
	if errors.Is(err, os.ErrPermission) || strings.Contains(lower, "permission denied") || strings.Contains(lower, "access is denied") || strings.Contains(lower, "operation not permitted") || strings.Contains(lower, "must be root") {
		return "permission_denied"
	}
	return "failed"
}
func Capability(sensor, state, reason string) Sensor {
	now := time.Now().UTC().Format(time.RFC3339Nano)
	s := Sensor{Sensor: sensor, State: state, ObservedAt: now, Reason: reason}
	if state == "running" {
		s.LastSuccessAt = now
	}
	return s
}

// Firewall reports the actual queried enforcement component. Other firewall layers
// remain outside that observation (for example macOS PF versus Application Firewall).
func Firewall(ctx context.Context, platform string, run Runner) (Sensor, Observation) {
	var out []byte
	var err error
	component := ""
	facts := map[string]any{}
	details := map[string]any{}
	switch platform {
	case "darwin":
		component = "macOS Application Firewall"
		out, err = run(ctx, "/usr/libexec/ApplicationFirewall/socketfilterfw", "--getglobalstate")
		if err == nil {
			if strings.Contains(string(out), "State = 1") {
				facts["firewall_enabled"] = true
			} else if strings.Contains(string(out), "State = 0") {
				facts["firewall_enabled"] = false
			}
		}
	case "linux":
		component = "UFW"
		out, err = run(ctx, "ufw", "status", "verbose")
		if errors.Is(err, exec.ErrNotFound) {
			component = "nftables"
			out, err = run(ctx, "nft", "-j", "list", "ruleset")
			if err == nil {
				var rules map[string]any
				if json.Unmarshal(out, &rules) == nil {
					details["ruleset_available"] = true
				} else {
					err = fmt.Errorf("invalid nftables JSON")
				}
			}
		} else if err == nil {
			if strings.Contains(string(out), "Status: active") {
				facts["firewall_enabled"] = true
			} else if strings.Contains(string(out), "Status: inactive") {
				facts["firewall_enabled"] = false
			}
		}
	case "windows":
		component = "Windows Firewall profiles"
		out, err = run(ctx, "powershell.exe", "-NoProfile", "-NonInteractive", "-Command", "Get-NetFirewallProfile -PolicyStore ActiveStore -ErrorAction Stop | Select-Object Name,@{Name='Enabled';Expression={$_.Enabled.ToString()}},DefaultInboundAction,DefaultOutboundAction | ConvertTo-Json -Compress")
		if err == nil {
			var profiles []struct {
				Name    string
				Enabled string
			}
			if json.Unmarshal(out, &profiles) != nil || len(profiles) != 3 {
				err = fmt.Errorf("incomplete firewall profile response")
			} else {
				enabled := true
				seen := map[string]bool{}
				for _, p := range profiles {
					if seen[p.Name] || (p.Name != "Domain" && p.Name != "Private" && p.Name != "Public") {
						err = fmt.Errorf("invalid firewall profile names")
						break
					}
					seen[p.Name] = true
					if p.Enabled != "True" && p.Enabled != "False" {
						err = fmt.Errorf("unknown firewall profile state")
						break
					}
					enabled = enabled && p.Enabled == "True"
				}
				if err == nil {
					facts["firewall_enabled"] = enabled
				}
				details["profiles"] = profiles
			}
		}
	default:
		err = exec.ErrNotFound
	}
	sum := sha256.Sum256(out)
	details["component"] = component
	details["snapshot_sha256"] = hex.EncodeToString(sum[:])
	// Rule listings and status output are bounded; no configuration changes are made.
	details["snapshot"] = string(out)
	details["enforcement_scope"] = component
	sensor := Capability("firewall", State(err, out), "Read-only enforcement snapshot")
	if err != nil {
		sensor.Reason = "Firewall observation failed: " + sensor.State
	}
	event := Observation{Type: "firewall.snapshot", Category: "firewall", Data: details, Facts: facts}
	if enabled, ok := facts["firewall_enabled"].(bool); ok {
		event.Entities = map[string]any{"firewall": map[string]any{"enabled": enabled}}
	}
	return sensor, event
}
func ReadTail(path string, maximum int) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return "", err
	}
	if !info.Mode().IsRegular() {
		return "", fmt.Errorf("not a regular log")
	}
	offset := info.Size() - int64(maximum)
	if offset < 0 {
		offset = 0
	}
	if _, err = f.Seek(offset, io.SeekStart); err != nil {
		return "", err
	}
	raw, err := io.ReadAll(io.LimitReader(f, int64(maximum)))
	return string(raw), err
}
func PatchHistory(platform string, read func(string, int) (string, error)) (Sensor, Observation) {
	path := ""
	switch platform {
	case "linux":
		path = "/var/log/dpkg.log"
	case "darwin":
		path = "/var/log/install.log"
	}
	if path == "" {
		return Capability("patches", "unsupported", "Native patch history adapter unavailable"), Observation{Type: "patch.history", Category: "patches", Data: map[string]any{"state": "unsupported"}}
	}
	history, err := read(path, 8192)
	if platform == "linux" && errors.Is(err, os.ErrNotExist) {
		path = "/var/log/dnf.rpm.log"
		history, err = read(path, 8192)
	}
	details := map[string]any{"source": path, "history": history, "history_limit_bytes": 8192, "reboot_required": nil, "scope": "package installation log; absence does not establish patch compliance"}
	if platform == "linux" {
		if _, err := os.Stat("/etc/debian_version"); err == nil {
			_, err = os.Stat("/var/run/reboot-required")
			if err == nil {
				details["reboot_required"] = true
			} else if errors.Is(err, os.ErrNotExist) {
				details["reboot_required"] = false
			}
		}
	}
	return Capability("patches", State(err, []byte(history)), "Bounded native installation history"), Observation{Type: "patch.history", Category: "patches", Data: details}
}
func Collect(ctx context.Context) ([]Sensor, []Observation) {
	firewall, fw := Firewall(ctx, runtime.GOOS, Run)
	patches, patch := PatchHistory(runtime.GOOS, ReadTail)
	return []Sensor{firewall, patches}, []Observation{fw, patch}
}
