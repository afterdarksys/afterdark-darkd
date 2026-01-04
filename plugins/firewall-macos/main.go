// macOS Firewall Plugin for afterdark-darkd
//
// Provides firewall management via pf (Packet Filter).
// Note: ipfw was deprecated in macOS 10.7 Lion and removed in later versions.
// pf is the standard firewall on macOS since 10.7.
//
// Requires root privileges for pfctl operations.
//
// Build: go build -o firewall-macos .
// Install: cp firewall-macos /var/lib/afterdark-darkd/plugins/
package main

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	sdk "github.com/afterdarksys/afterdark-darkd/pkg/pluginsdk"
)

const (
	// pf configuration paths
	pfConfDir     = "/etc/pf.afterdark.d"
	pfAnchorFile  = "/etc/pf.afterdark.d/afterdark.conf"
	pfBlockedFile = "/etc/pf.afterdark.d/blocked_ips"
	pfRulesFile   = "/etc/pf.afterdark.d/rules.conf"

	// pf anchor name
	pfAnchor = "com.afterdark"
)

// MacOSFirewall implements the FirewallPlugin interface for macOS
type MacOSFirewall struct {
	sdk.BaseFirewallPlugin

	mu             sync.RWMutex
	enabled        bool
	rules          map[string]*sdk.FirewallRule
	blockedIPs     map[string]*sdk.BlockedIP
	defaultDenyIn  bool
	defaultDenyOut bool
	pfVersion      string
	logger         func(string, ...interface{})
}

func (f *MacOSFirewall) Info() sdk.PluginInfo {
	return sdk.PluginInfo{
		Name:        "firewall-macos",
		Version:     "1.0.0",
		Type:        sdk.PluginTypeFirewall,
		Description: "macOS firewall plugin using pf (Packet Filter)",
		Author:      "After Dark Systems, LLC",
		License:     "MIT",
		Capabilities: []string{
			"block_ip", "unblock_ip", "list_blocked",
			"add_rule", "remove_rule", "list_rules",
			"sync_blocklist", "open_port", "close_port",
			"pf", "anchor",
		},
	}
}

func (f *MacOSFirewall) Configure(config map[string]interface{}) error {
	if err := f.BaseFirewallPlugin.Configure(config); err != nil {
		return err
	}

	f.mu.Lock()
	defer f.mu.Unlock()

	f.rules = make(map[string]*sdk.FirewallRule)
	f.blockedIPs = make(map[string]*sdk.BlockedIP)
	f.logger = func(format string, args ...interface{}) {
		fmt.Printf("[firewall-macos] "+format+"\n", args...)
	}

	// Check for pfctl
	if _, err := exec.LookPath("pfctl"); err != nil {
		return fmt.Errorf("pfctl not found: %w", err)
	}

	// Get pf version
	out, err := exec.Command("pfctl", "-s", "info").Output()
	if err == nil {
		lines := strings.Split(string(out), "\n")
		if len(lines) > 0 {
			f.pfVersion = strings.TrimSpace(lines[0])
		}
	} else {
		f.pfVersion = "pf (version unknown)"
	}

	// Create configuration directory
	if err := os.MkdirAll(pfConfDir, 0755); err != nil {
		return fmt.Errorf("failed to create config dir: %w", err)
	}

	f.SetState(sdk.PluginStateReady, "pf configured")
	return nil
}

func (f *MacOSFirewall) Enable(ctx context.Context, enable bool, defaultDenyInbound bool, defaultDenyOutbound bool) (*sdk.FirewallStatus, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	if enable {
		if err := f.initPF(ctx, defaultDenyInbound, defaultDenyOutbound); err != nil {
			return nil, fmt.Errorf("failed to initialize pf: %w", err)
		}

		// Enable pf if not already enabled
		if err := f.runPfctl(ctx, "-e"); err != nil {
			// Ignore "already enabled" error
			if !strings.Contains(err.Error(), "already enabled") {
				return nil, err
			}
		}
	} else {
		// Remove our anchor
		f.runPfctl(ctx, "-a", pfAnchor, "-F", "all")
	}

	f.enabled = enable
	f.defaultDenyIn = defaultDenyInbound
	f.defaultDenyOut = defaultDenyOutbound

	return f.getStatusLocked(), nil
}

func (f *MacOSFirewall) initPF(ctx context.Context, defaultDenyIn bool, defaultDenyOut bool) error {
	// Create anchor configuration
	var conf strings.Builder

	conf.WriteString("# AfterDark Security Daemon - pf anchor configuration\n")
	conf.WriteString("# Auto-generated - do not edit manually\n\n")

	// Table for blocked IPs
	conf.WriteString(fmt.Sprintf("table <afterdark_blocked> persist file \"%s\"\n\n", pfBlockedFile))

	// Block rules for table
	conf.WriteString("# Block all traffic from/to blocked IPs\n")
	conf.WriteString("block in quick from <afterdark_blocked>\n")
	conf.WriteString("block out quick to <afterdark_blocked>\n\n")

	// Include custom rules
	conf.WriteString(fmt.Sprintf("include \"%s\"\n", pfRulesFile))

	// Write anchor config
	if err := os.WriteFile(pfAnchorFile, []byte(conf.String()), 0644); err != nil {
		return fmt.Errorf("failed to write anchor config: %w", err)
	}

	// Create empty blocked IPs file if not exists
	if _, err := os.Stat(pfBlockedFile); os.IsNotExist(err) {
		if err := os.WriteFile(pfBlockedFile, []byte(""), 0644); err != nil {
			return err
		}
	}

	// Create empty rules file if not exists
	if _, err := os.Stat(pfRulesFile); os.IsNotExist(err) {
		if err := os.WriteFile(pfRulesFile, []byte("# AfterDark custom rules\n"), 0644); err != nil {
			return err
		}
	}

	// Load anchor
	if err := f.runPfctl(ctx, "-a", pfAnchor, "-f", pfAnchorFile); err != nil {
		return fmt.Errorf("failed to load anchor: %w", err)
	}

	// Reload blocked IPs table
	return f.reloadBlockedTable(ctx)
}

func (f *MacOSFirewall) reloadBlockedTable(ctx context.Context) error {
	return f.runPfctl(ctx, "-a", pfAnchor, "-t", "afterdark_blocked", "-T", "replace", "-f", pfBlockedFile)
}

func (f *MacOSFirewall) Status(ctx context.Context) (*sdk.FirewallStatus, error) {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return f.getStatusLocked(), nil
}

func (f *MacOSFirewall) getStatusLocked() *sdk.FirewallStatus {
	activeRules := 0
	for _, r := range f.rules {
		if r.Enabled {
			activeRules++
		}
	}

	// Check if pf is enabled
	pfEnabled := false
	out, err := exec.Command("pfctl", "-s", "info").Output()
	if err == nil {
		pfEnabled = strings.Contains(string(out), "Status: Enabled")
	}

	return &sdk.FirewallStatus{
		Enabled:             f.enabled && pfEnabled,
		Backend:             "pf",
		Version:             f.pfVersion,
		TotalRules:          len(f.rules),
		ActiveRules:         activeRules,
		BlockedIPs:          len(f.blockedIPs),
		DefaultDenyInbound:  f.defaultDenyIn,
		DefaultDenyOutbound: f.defaultDenyOut,
		LastUpdated:         time.Now(),
		Capabilities: map[string]string{
			"ipv4":    "true",
			"ipv6":    "true",
			"tables":  "true",
			"anchors": "true",
			"logging": "true",
		},
	}
}

func (f *MacOSFirewall) BlockIP(ctx context.Context, ip string, reason string, sourceService string, durationSeconds int64, threatScore int, categories []string) (*sdk.BlockedIP, error) {
	// Validate IP
	if net.ParseIP(ip) == nil {
		_, _, err := net.ParseCIDR(ip)
		if err != nil {
			return nil, fmt.Errorf("invalid IP address: %s", ip)
		}
	}

	f.mu.Lock()
	defer f.mu.Unlock()

	if existing, ok := f.blockedIPs[ip]; ok {
		return existing, nil
	}

	// Add to blocked IPs file
	if err := f.addBlockedIPToFile(ip); err != nil {
		return nil, err
	}

	// Reload table
	if f.enabled {
		if err := f.runPfctl(ctx, "-a", pfAnchor, "-t", "afterdark_blocked", "-T", "add", ip); err != nil {
			f.logger("warning: failed to add to table immediately: %v", err)
		}
	}

	blocked := &sdk.BlockedIP{
		IP:            ip,
		Reason:        reason,
		SourceService: sourceService,
		BlockedAt:     time.Now(),
		ThreatScore:   threatScore,
		Categories:    categories,
	}

	if durationSeconds > 0 {
		blocked.ExpiresAt = time.Now().Add(time.Duration(durationSeconds) * time.Second)
	}

	f.blockedIPs[ip] = blocked
	f.logger("blocked IP %s (reason: %s)", ip, reason)

	return blocked, nil
}

func (f *MacOSFirewall) addBlockedIPToFile(ip string) error {
	file, err := os.OpenFile(pfBlockedFile, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0644)
	if err != nil {
		return err
	}
	defer file.Close()

	_, err = file.WriteString(ip + "\n")
	return err
}

func (f *MacOSFirewall) removeBlockedIPFromFile(ip string) error {
	// Read current file
	data, err := os.ReadFile(pfBlockedFile)
	if err != nil {
		return err
	}

	// Filter out the IP
	var newLines []string
	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line != "" && line != ip {
			newLines = append(newLines, line)
		}
	}

	// Write back
	return os.WriteFile(pfBlockedFile, []byte(strings.Join(newLines, "\n")+"\n"), 0644)
}

func (f *MacOSFirewall) UnblockIP(ctx context.Context, ip string) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	if _, ok := f.blockedIPs[ip]; !ok {
		return nil
	}

	// Remove from file
	if err := f.removeBlockedIPFromFile(ip); err != nil {
		return err
	}

	// Remove from table
	if f.enabled {
		if err := f.runPfctl(ctx, "-a", pfAnchor, "-t", "afterdark_blocked", "-T", "delete", ip); err != nil {
			f.logger("warning: failed to remove from table: %v", err)
		}
	}

	delete(f.blockedIPs, ip)
	f.logger("unblocked IP %s", ip)

	return nil
}

func (f *MacOSFirewall) ListBlockedIPs(ctx context.Context, limit int, offset int, sourceService string) ([]sdk.BlockedIP, int, error) {
	f.mu.RLock()
	defer f.mu.RUnlock()

	var result []sdk.BlockedIP
	for _, blocked := range f.blockedIPs {
		if sourceService != "" && blocked.SourceService != sourceService {
			continue
		}
		result = append(result, *blocked)
	}

	total := len(result)

	if offset > len(result) {
		return []sdk.BlockedIP{}, total, nil
	}
	result = result[offset:]
	if limit > 0 && len(result) > limit {
		result = result[:limit]
	}

	return result, total, nil
}

func (f *MacOSFirewall) IsIPBlocked(ctx context.Context, ip string) (bool, *sdk.BlockedIP, error) {
	f.mu.RLock()
	defer f.mu.RUnlock()

	if blocked, ok := f.blockedIPs[ip]; ok {
		return true, blocked, nil
	}
	return false, nil, nil
}

func (f *MacOSFirewall) AddRule(ctx context.Context, rule *sdk.FirewallRule) (*sdk.FirewallRule, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	if rule.ID == "" {
		rule.ID = uuid.New().String()[:8]
	}
	rule.CreatedAt = time.Now()

	f.rules[rule.ID] = rule

	// Write rules to file and reload
	if err := f.writeRulesFile(); err != nil {
		delete(f.rules, rule.ID)
		return nil, err
	}

	if f.enabled {
		if err := f.reloadRules(ctx); err != nil {
			f.logger("warning: failed to reload rules: %v", err)
		}
	}

	f.logger("added rule %s: %s %s -> %s", rule.ID, rule.Action, rule.SourceIP, rule.DestPort)
	return rule, nil
}

func (f *MacOSFirewall) writeRulesFile() error {
	var conf strings.Builder

	conf.WriteString("# AfterDark custom rules\n")
	conf.WriteString("# Auto-generated - do not edit manually\n\n")

	for _, rule := range f.rules {
		if !rule.Enabled {
			continue
		}
		pfRule := f.buildPFRule(rule)
		conf.WriteString(fmt.Sprintf("# Rule: %s (%s)\n", rule.ID, rule.Name))
		conf.WriteString(pfRule + "\n\n")
	}

	return os.WriteFile(pfRulesFile, []byte(conf.String()), 0644)
}

func (f *MacOSFirewall) buildPFRule(rule *sdk.FirewallRule) string {
	var parts []string

	// Action
	action := rule.Action
	if action == "allow" {
		action = "pass"
	} else if action == "deny" || action == "reject" {
		action = "block"
	}
	parts = append(parts, action)

	// Direction
	if rule.Direction == "inbound" {
		parts = append(parts, "in")
	} else if rule.Direction == "outbound" {
		parts = append(parts, "out")
	}

	// Quick (process immediately)
	parts = append(parts, "quick")

	// Protocol
	if rule.Protocol != "" && rule.Protocol != "any" {
		parts = append(parts, "proto", rule.Protocol)
	}

	// Source
	if rule.SourceIP != "" && rule.SourceIP != "any" {
		parts = append(parts, "from", rule.SourceIP)
	} else {
		parts = append(parts, "from", "any")
	}

	if rule.SourcePort != "" && rule.SourcePort != "any" {
		parts = append(parts, "port", rule.SourcePort)
	}

	// Destination
	if rule.DestIP != "" && rule.DestIP != "any" {
		parts = append(parts, "to", rule.DestIP)
	} else {
		parts = append(parts, "to", "any")
	}

	if rule.DestPort != "" && rule.DestPort != "any" {
		parts = append(parts, "port", rule.DestPort)
	}

	return strings.Join(parts, " ")
}

func (f *MacOSFirewall) reloadRules(ctx context.Context) error {
	return f.runPfctl(ctx, "-a", pfAnchor, "-f", pfAnchorFile)
}

func (f *MacOSFirewall) RemoveRule(ctx context.Context, ruleID string) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	if _, ok := f.rules[ruleID]; !ok {
		return fmt.Errorf("rule not found: %s", ruleID)
	}

	delete(f.rules, ruleID)

	if err := f.writeRulesFile(); err != nil {
		return err
	}

	if f.enabled {
		if err := f.reloadRules(ctx); err != nil {
			f.logger("warning: failed to reload rules: %v", err)
		}
	}

	f.logger("removed rule %s", ruleID)
	return nil
}

func (f *MacOSFirewall) UpdateRule(ctx context.Context, rule *sdk.FirewallRule) (*sdk.FirewallRule, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	if _, ok := f.rules[rule.ID]; !ok {
		return nil, fmt.Errorf("rule not found: %s", rule.ID)
	}

	f.rules[rule.ID] = rule

	if err := f.writeRulesFile(); err != nil {
		return nil, err
	}

	if f.enabled {
		if err := f.reloadRules(ctx); err != nil {
			f.logger("warning: failed to reload rules: %v", err)
		}
	}

	return rule, nil
}

func (f *MacOSFirewall) ListRules(ctx context.Context, limit int, offset int, direction string, enabledOnly bool) ([]sdk.FirewallRule, int, error) {
	f.mu.RLock()
	defer f.mu.RUnlock()

	var result []sdk.FirewallRule
	for _, rule := range f.rules {
		if direction != "" && rule.Direction != direction {
			continue
		}
		if enabledOnly && !rule.Enabled {
			continue
		}
		result = append(result, *rule)
	}

	total := len(result)

	if offset > len(result) {
		return []sdk.FirewallRule{}, total, nil
	}
	result = result[offset:]
	if limit > 0 && len(result) > limit {
		result = result[:limit]
	}

	return result, total, nil
}

func (f *MacOSFirewall) GetRule(ctx context.Context, ruleID string) (*sdk.FirewallRule, error) {
	f.mu.RLock()
	defer f.mu.RUnlock()

	rule, ok := f.rules[ruleID]
	if !ok {
		return nil, fmt.Errorf("rule not found: %s", ruleID)
	}
	return rule, nil
}

func (f *MacOSFirewall) SyncBlocklist(ctx context.Context, blockedIPs []sdk.BlockedIP, replace bool) (added int, removed int, unchanged int, err error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	newIPs := make(map[string]*sdk.BlockedIP)
	for i := range blockedIPs {
		newIPs[blockedIPs[i].IP] = &blockedIPs[i]
	}

	if replace {
		for ip := range f.blockedIPs {
			if _, ok := newIPs[ip]; !ok {
				delete(f.blockedIPs, ip)
				removed++
			}
		}
	}

	for ip, blocked := range newIPs {
		if _, ok := f.blockedIPs[ip]; ok {
			unchanged++
			continue
		}

		blocked.BlockedAt = time.Now()
		f.blockedIPs[ip] = blocked
		added++
	}

	// Write all blocked IPs to file
	var ips []string
	for ip := range f.blockedIPs {
		ips = append(ips, ip)
	}

	if err := os.WriteFile(pfBlockedFile, []byte(strings.Join(ips, "\n")+"\n"), 0644); err != nil {
		return 0, 0, 0, err
	}

	if f.enabled {
		if err := f.reloadBlockedTable(ctx); err != nil {
			f.logger("warning: failed to reload blocked table: %v", err)
		}
	}

	f.logger("blocklist sync: added=%d, removed=%d, unchanged=%d", added, removed, unchanged)
	return added, removed, unchanged, nil
}

func (f *MacOSFirewall) FlushRules(ctx context.Context, flushBlocks bool, flushRules bool, keepEssential bool) (rulesFlushed int, blocksFlushed int, err error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	if flushBlocks {
		blocksFlushed = len(f.blockedIPs)
		f.blockedIPs = make(map[string]*sdk.BlockedIP)

		// Clear blocked file
		os.WriteFile(pfBlockedFile, []byte(""), 0644)

		if f.enabled {
			f.runPfctl(ctx, "-a", pfAnchor, "-t", "afterdark_blocked", "-T", "flush")
		}
	}

	if flushRules {
		rulesFlushed = len(f.rules)
		f.rules = make(map[string]*sdk.FirewallRule)

		// Clear rules file
		os.WriteFile(pfRulesFile, []byte("# AfterDark custom rules\n"), 0644)

		if f.enabled {
			f.reloadRules(ctx)
		}
	}

	f.logger("flushed: rules=%d, blocks=%d", rulesFlushed, blocksFlushed)
	return rulesFlushed, blocksFlushed, nil
}

func (f *MacOSFirewall) OpenPort(ctx context.Context, port int, protocol string, direction string, sourceIP string, description string) (*sdk.FirewallRule, error) {
	if protocol == "" {
		protocol = "tcp"
	}
	if direction == "" {
		direction = "inbound"
	}

	rule := &sdk.FirewallRule{
		Name:        fmt.Sprintf("open-port-%d-%s", port, protocol),
		Description: description,
		Direction:   direction,
		Action:      "allow",
		Protocol:    protocol,
		SourceIP:    sourceIP,
		DestPort:    strconv.Itoa(port),
		Enabled:     true,
		Reason:      "port opened via API",
	}

	return f.AddRule(ctx, rule)
}

func (f *MacOSFirewall) ClosePort(ctx context.Context, port int, protocol string, direction string) error {
	if protocol == "" {
		protocol = "tcp"
	}
	if direction == "" {
		direction = "inbound"
	}

	f.mu.Lock()
	defer f.mu.Unlock()

	for id, rule := range f.rules {
		if rule.DestPort == strconv.Itoa(port) &&
			rule.Protocol == protocol &&
			rule.Direction == direction &&
			rule.Action == "allow" {

			delete(f.rules, id)

			if err := f.writeRulesFile(); err != nil {
				return err
			}

			if f.enabled {
				f.reloadRules(ctx)
			}

			f.logger("closed port %d/%s", port, protocol)
			return nil
		}
	}

	return nil
}

func (f *MacOSFirewall) runPfctl(ctx context.Context, args ...string) error {
	cmd := exec.CommandContext(ctx, "pfctl", args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("pfctl %v: %w (output: %s)", args, err, string(output))
	}
	return nil
}

// loadBlockedIPsFromFile loads existing blocked IPs from the file
func (f *MacOSFirewall) loadBlockedIPsFromFile() error {
	if _, err := os.Stat(pfBlockedFile); os.IsNotExist(err) {
		return nil
	}

	file, err := os.Open(pfBlockedFile)
	if err != nil {
		return err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		ip := strings.TrimSpace(scanner.Text())
		if ip != "" && !strings.HasPrefix(ip, "#") {
			f.blockedIPs[ip] = &sdk.BlockedIP{
				IP:            ip,
				Reason:        "loaded from file",
				SourceService: "file",
				BlockedAt:     time.Now(),
			}
		}
	}

	return scanner.Err()
}

func main() {
	// Ensure we clean up temp files on exit
	defer func() {
		// Cleanup any temporary files created during operation
		tmpFiles, _ := filepath.Glob("/tmp/afterdark-pf-*")
		for _, f := range tmpFiles {
			os.Remove(f)
		}
	}()

	sdk.ServeFirewallPlugin(&MacOSFirewall{})
}
