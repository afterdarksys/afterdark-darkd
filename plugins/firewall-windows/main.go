// Windows Firewall Plugin for afterdark-darkd
//
// Provides firewall management via Windows Firewall (netsh advfirewall).
// Requires Administrator privileges for firewall operations.
//
// Build: GOOS=windows GOARCH=amd64 go build -o firewall-windows.exe .
// Install: copy firewall-windows.exe C:\ProgramData\AfterDark\plugins\
package main

import (
	"context"
	"fmt"
	"net"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	sdk "github.com/afterdarksys/afterdark-darkd/pkg/pluginsdk"
)

const (
	rulePrefix = "AfterDark-"
)

// WindowsFirewall implements the FirewallPlugin interface for Windows
type WindowsFirewall struct {
	sdk.BaseFirewallPlugin

	mu             sync.RWMutex
	enabled        bool
	rules          map[string]*sdk.FirewallRule
	blockedIPs     map[string]*sdk.BlockedIP
	defaultDenyIn  bool
	defaultDenyOut bool
	version        string
	logger         func(string, ...interface{})
}

func (f *WindowsFirewall) Info() sdk.PluginInfo {
	return sdk.PluginInfo{
		Name:        "firewall-windows",
		Version:     "1.0.0",
		Type:        sdk.PluginTypeFirewall,
		Description: "Windows Firewall plugin using netsh advfirewall",
		Author:      "After Dark Systems, LLC",
		License:     "MIT",
		Capabilities: []string{
			"block_ip", "unblock_ip", "list_blocked",
			"add_rule", "remove_rule", "list_rules",
			"sync_blocklist", "open_port", "close_port",
			"windows-firewall", "netsh",
		},
	}
}

func (f *WindowsFirewall) Configure(config map[string]interface{}) error {
	if err := f.BaseFirewallPlugin.Configure(config); err != nil {
		return err
	}

	f.mu.Lock()
	defer f.mu.Unlock()

	f.rules = make(map[string]*sdk.FirewallRule)
	f.blockedIPs = make(map[string]*sdk.BlockedIP)
	f.logger = func(format string, args ...interface{}) {
		fmt.Printf("[firewall-windows] "+format+"\n", args...)
	}

	// Check for netsh
	if _, err := exec.LookPath("netsh"); err != nil {
		return fmt.Errorf("netsh not found: %w", err)
	}

	// Get Windows Firewall info
	out, err := exec.Command("netsh", "advfirewall", "show", "currentprofile").Output()
	if err == nil {
		f.version = "Windows Firewall"
		if strings.Contains(string(out), "Domain Profile") {
			f.version += " (Domain)"
		} else if strings.Contains(string(out), "Private Profile") {
			f.version += " (Private)"
		} else if strings.Contains(string(out), "Public Profile") {
			f.version += " (Public)"
		}
	} else {
		f.version = "Windows Firewall"
	}

	// Load existing AfterDark rules
	f.loadExistingRules()

	f.SetState(sdk.PluginStateReady, "Windows Firewall configured")
	return nil
}

func (f *WindowsFirewall) loadExistingRules() {
	// List existing AfterDark rules
	out, err := exec.Command("netsh", "advfirewall", "firewall", "show", "rule", "name=all").Output()
	if err != nil {
		return
	}

	lines := strings.Split(string(out), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "Rule Name:") {
			name := strings.TrimPrefix(line, "Rule Name:")
			name = strings.TrimSpace(name)
			if strings.HasPrefix(name, rulePrefix) {
				// This is one of our rules
				id := strings.TrimPrefix(name, rulePrefix)
				f.rules[id] = &sdk.FirewallRule{
					ID:      id,
					Name:    name,
					Enabled: true,
				}
			}
		}
	}
}

func (f *WindowsFirewall) Enable(ctx context.Context, enable bool, defaultDenyInbound bool, defaultDenyOutbound bool) (*sdk.FirewallStatus, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	if enable {
		// Enable Windows Firewall
		if err := f.runNetsh(ctx, "advfirewall", "set", "allprofiles", "state", "on"); err != nil {
			return nil, err
		}

		// Set default policies
		inPolicy := "allow"
		if defaultDenyInbound {
			inPolicy = "block"
		}
		outPolicy := "allow"
		if defaultDenyOutbound {
			outPolicy = "block"
		}

		if err := f.runNetsh(ctx, "advfirewall", "set", "allprofiles", "firewallpolicy", fmt.Sprintf("%sinbound,%soutbound", inPolicy, outPolicy)); err != nil {
			return nil, err
		}
	} else {
		// Disable Windows Firewall (not recommended)
		if err := f.runNetsh(ctx, "advfirewall", "set", "allprofiles", "state", "off"); err != nil {
			return nil, err
		}
	}

	f.enabled = enable
	f.defaultDenyIn = defaultDenyInbound
	f.defaultDenyOut = defaultDenyOutbound

	return f.getStatusLocked(ctx), nil
}

func (f *WindowsFirewall) Status(ctx context.Context) (*sdk.FirewallStatus, error) {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return f.getStatusLocked(ctx), nil
}

func (f *WindowsFirewall) getStatusLocked(ctx context.Context) *sdk.FirewallStatus {
	activeRules := 0
	for _, r := range f.rules {
		if r.Enabled {
			activeRules++
		}
	}

	// Check firewall state
	fwEnabled := false
	out, err := exec.CommandContext(ctx, "netsh", "advfirewall", "show", "currentprofile", "state").Output()
	if err == nil {
		fwEnabled = strings.Contains(string(out), "ON")
	}

	return &sdk.FirewallStatus{
		Enabled:             f.enabled && fwEnabled,
		Backend:             "windows-firewall",
		Version:             f.version,
		TotalRules:          len(f.rules),
		ActiveRules:         activeRules,
		BlockedIPs:          len(f.blockedIPs),
		DefaultDenyInbound:  f.defaultDenyIn,
		DefaultDenyOutbound: f.defaultDenyOut,
		LastUpdated:         time.Now(),
		Capabilities: map[string]string{
			"ipv4":     "true",
			"ipv6":     "true",
			"profiles": "true",
			"logging":  "true",
		},
	}
}

func (f *WindowsFirewall) BlockIP(ctx context.Context, ip string, reason string, sourceService string, durationSeconds int64, threatScore int, categories []string) (*sdk.BlockedIP, error) {
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

	// Create block rule
	ruleName := fmt.Sprintf("%sBlock-%s", rulePrefix, strings.ReplaceAll(ip, ".", "-"))
	ruleName = strings.ReplaceAll(ruleName, ":", "-") // For IPv6
	ruleName = strings.ReplaceAll(ruleName, "/", "_") // For CIDR

	// Block inbound
	if err := f.runNetsh(ctx, "advfirewall", "firewall", "add", "rule",
		fmt.Sprintf("name=%s-In", ruleName),
		"dir=in",
		"action=block",
		fmt.Sprintf("remoteip=%s", ip),
		"enable=yes",
	); err != nil {
		return nil, err
	}

	// Block outbound
	if err := f.runNetsh(ctx, "advfirewall", "firewall", "add", "rule",
		fmt.Sprintf("name=%s-Out", ruleName),
		"dir=out",
		"action=block",
		fmt.Sprintf("remoteip=%s", ip),
		"enable=yes",
	); err != nil {
		// Try to clean up inbound rule
		f.runNetsh(ctx, "advfirewall", "firewall", "delete", "rule", fmt.Sprintf("name=%s-In", ruleName))
		return nil, err
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

func (f *WindowsFirewall) UnblockIP(ctx context.Context, ip string) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	if _, ok := f.blockedIPs[ip]; !ok {
		return nil
	}

	ruleName := fmt.Sprintf("%sBlock-%s", rulePrefix, strings.ReplaceAll(ip, ".", "-"))
	ruleName = strings.ReplaceAll(ruleName, ":", "-")
	ruleName = strings.ReplaceAll(ruleName, "/", "_")

	// Delete both rules
	f.runNetsh(ctx, "advfirewall", "firewall", "delete", "rule", fmt.Sprintf("name=%s-In", ruleName))
	f.runNetsh(ctx, "advfirewall", "firewall", "delete", "rule", fmt.Sprintf("name=%s-Out", ruleName))

	delete(f.blockedIPs, ip)
	f.logger("unblocked IP %s", ip)

	return nil
}

func (f *WindowsFirewall) ListBlockedIPs(ctx context.Context, limit int, offset int, sourceService string) ([]sdk.BlockedIP, int, error) {
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

func (f *WindowsFirewall) IsIPBlocked(ctx context.Context, ip string) (bool, *sdk.BlockedIP, error) {
	f.mu.RLock()
	defer f.mu.RUnlock()

	if blocked, ok := f.blockedIPs[ip]; ok {
		return true, blocked, nil
	}
	return false, nil, nil
}

func (f *WindowsFirewall) AddRule(ctx context.Context, rule *sdk.FirewallRule) (*sdk.FirewallRule, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	if rule.ID == "" {
		rule.ID = uuid.New().String()[:8]
	}
	rule.CreatedAt = time.Now()

	if rule.Enabled {
		if err := f.applyRule(ctx, rule); err != nil {
			return nil, err
		}
	}

	f.rules[rule.ID] = rule
	f.logger("added rule %s: %s", rule.ID, rule.Name)

	return rule, nil
}

func (f *WindowsFirewall) applyRule(ctx context.Context, rule *sdk.FirewallRule) error {
	ruleName := fmt.Sprintf("%s%s", rulePrefix, rule.ID)

	args := []string{
		"advfirewall", "firewall", "add", "rule",
		fmt.Sprintf("name=%s", ruleName),
	}

	// Direction
	if rule.Direction == "inbound" {
		args = append(args, "dir=in")
	} else if rule.Direction == "outbound" {
		args = append(args, "dir=out")
	} else {
		// Create both inbound and outbound
		if err := f.applyRuleWithDir(ctx, rule, "in"); err != nil {
			return err
		}
		return f.applyRuleWithDir(ctx, rule, "out")
	}

	// Action
	action := rule.Action
	if action == "deny" || action == "drop" || action == "reject" {
		action = "block"
	}
	args = append(args, fmt.Sprintf("action=%s", action))

	// Protocol
	if rule.Protocol != "" && rule.Protocol != "any" {
		args = append(args, fmt.Sprintf("protocol=%s", rule.Protocol))
	}

	// Source IP
	if rule.SourceIP != "" && rule.SourceIP != "any" {
		args = append(args, fmt.Sprintf("remoteip=%s", rule.SourceIP))
	}

	// Source Port
	if rule.SourcePort != "" && rule.SourcePort != "any" {
		args = append(args, fmt.Sprintf("remoteport=%s", rule.SourcePort))
	}

	// Dest IP (local IP for Windows Firewall)
	if rule.DestIP != "" && rule.DestIP != "any" {
		args = append(args, fmt.Sprintf("localip=%s", rule.DestIP))
	}

	// Dest Port
	if rule.DestPort != "" && rule.DestPort != "any" {
		args = append(args, fmt.Sprintf("localport=%s", rule.DestPort))
	}

	// Interface
	if rule.Interface != "" {
		args = append(args, fmt.Sprintf("interface=%s", rule.Interface))
	}

	args = append(args, "enable=yes")

	return f.runNetsh(ctx, args...)
}

func (f *WindowsFirewall) applyRuleWithDir(ctx context.Context, rule *sdk.FirewallRule, dir string) error {
	ruleName := fmt.Sprintf("%s%s-%s", rulePrefix, rule.ID, strings.ToUpper(dir[:1])+dir[1:])

	args := []string{
		"advfirewall", "firewall", "add", "rule",
		fmt.Sprintf("name=%s", ruleName),
		fmt.Sprintf("dir=%s", dir),
	}

	action := rule.Action
	if action == "deny" || action == "drop" || action == "reject" {
		action = "block"
	}
	args = append(args, fmt.Sprintf("action=%s", action))

	if rule.Protocol != "" && rule.Protocol != "any" {
		args = append(args, fmt.Sprintf("protocol=%s", rule.Protocol))
	}

	if rule.SourceIP != "" && rule.SourceIP != "any" {
		args = append(args, fmt.Sprintf("remoteip=%s", rule.SourceIP))
	}

	if rule.DestPort != "" && rule.DestPort != "any" {
		args = append(args, fmt.Sprintf("localport=%s", rule.DestPort))
	}

	args = append(args, "enable=yes")

	return f.runNetsh(ctx, args...)
}

func (f *WindowsFirewall) RemoveRule(ctx context.Context, ruleID string) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	rule, ok := f.rules[ruleID]
	if !ok {
		return fmt.Errorf("rule not found: %s", ruleID)
	}

	ruleName := fmt.Sprintf("%s%s", rulePrefix, rule.ID)

	// Try to delete the rule (may have -In or -Out suffix)
	f.runNetsh(ctx, "advfirewall", "firewall", "delete", "rule", fmt.Sprintf("name=%s", ruleName))
	f.runNetsh(ctx, "advfirewall", "firewall", "delete", "rule", fmt.Sprintf("name=%s-In", ruleName))
	f.runNetsh(ctx, "advfirewall", "firewall", "delete", "rule", fmt.Sprintf("name=%s-Out", ruleName))

	delete(f.rules, ruleID)
	f.logger("removed rule %s", ruleID)

	return nil
}

func (f *WindowsFirewall) UpdateRule(ctx context.Context, rule *sdk.FirewallRule) (*sdk.FirewallRule, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	existing, ok := f.rules[rule.ID]
	if !ok {
		return nil, fmt.Errorf("rule not found: %s", rule.ID)
	}

	// Remove old rule
	ruleName := fmt.Sprintf("%s%s", rulePrefix, existing.ID)
	f.runNetsh(ctx, "advfirewall", "firewall", "delete", "rule", fmt.Sprintf("name=%s", ruleName))
	f.runNetsh(ctx, "advfirewall", "firewall", "delete", "rule", fmt.Sprintf("name=%s-In", ruleName))
	f.runNetsh(ctx, "advfirewall", "firewall", "delete", "rule", fmt.Sprintf("name=%s-Out", ruleName))

	// Apply new rule
	if rule.Enabled {
		if err := f.applyRule(ctx, rule); err != nil {
			return nil, err
		}
	}

	f.rules[rule.ID] = rule
	return rule, nil
}

func (f *WindowsFirewall) ListRules(ctx context.Context, limit int, offset int, direction string, enabledOnly bool) ([]sdk.FirewallRule, int, error) {
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

func (f *WindowsFirewall) GetRule(ctx context.Context, ruleID string) (*sdk.FirewallRule, error) {
	f.mu.RLock()
	defer f.mu.RUnlock()

	rule, ok := f.rules[ruleID]
	if !ok {
		return nil, fmt.Errorf("rule not found: %s", ruleID)
	}
	return rule, nil
}

func (f *WindowsFirewall) SyncBlocklist(ctx context.Context, blockedIPs []sdk.BlockedIP, replace bool) (added int, removed int, unchanged int, err error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	newIPs := make(map[string]*sdk.BlockedIP)
	for i := range blockedIPs {
		newIPs[blockedIPs[i].IP] = &blockedIPs[i]
	}

	if replace {
		for ip := range f.blockedIPs {
			if _, ok := newIPs[ip]; !ok {
				ruleName := fmt.Sprintf("%sBlock-%s", rulePrefix, strings.ReplaceAll(ip, ".", "-"))
				ruleName = strings.ReplaceAll(ruleName, ":", "-")
				ruleName = strings.ReplaceAll(ruleName, "/", "_")

				f.runNetsh(ctx, "advfirewall", "firewall", "delete", "rule", fmt.Sprintf("name=%s-In", ruleName))
				f.runNetsh(ctx, "advfirewall", "firewall", "delete", "rule", fmt.Sprintf("name=%s-Out", ruleName))

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

		ruleName := fmt.Sprintf("%sBlock-%s", rulePrefix, strings.ReplaceAll(ip, ".", "-"))
		ruleName = strings.ReplaceAll(ruleName, ":", "-")
		ruleName = strings.ReplaceAll(ruleName, "/", "_")

		// Add block rules
		f.runNetsh(ctx, "advfirewall", "firewall", "add", "rule",
			fmt.Sprintf("name=%s-In", ruleName), "dir=in", "action=block",
			fmt.Sprintf("remoteip=%s", ip), "enable=yes")

		f.runNetsh(ctx, "advfirewall", "firewall", "add", "rule",
			fmt.Sprintf("name=%s-Out", ruleName), "dir=out", "action=block",
			fmt.Sprintf("remoteip=%s", ip), "enable=yes")

		blocked.BlockedAt = time.Now()
		f.blockedIPs[ip] = blocked
		added++
	}

	f.logger("blocklist sync: added=%d, removed=%d, unchanged=%d", added, removed, unchanged)
	return added, removed, unchanged, nil
}

func (f *WindowsFirewall) FlushRules(ctx context.Context, flushBlocks bool, flushRules bool, keepEssential bool) (rulesFlushed int, blocksFlushed int, err error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	if flushBlocks {
		for ip := range f.blockedIPs {
			ruleName := fmt.Sprintf("%sBlock-%s", rulePrefix, strings.ReplaceAll(ip, ".", "-"))
			ruleName = strings.ReplaceAll(ruleName, ":", "-")
			ruleName = strings.ReplaceAll(ruleName, "/", "_")

			f.runNetsh(ctx, "advfirewall", "firewall", "delete", "rule", fmt.Sprintf("name=%s-In", ruleName))
			f.runNetsh(ctx, "advfirewall", "firewall", "delete", "rule", fmt.Sprintf("name=%s-Out", ruleName))
			blocksFlushed++
		}
		f.blockedIPs = make(map[string]*sdk.BlockedIP)
	}

	if flushRules {
		for id, rule := range f.rules {
			ruleName := fmt.Sprintf("%s%s", rulePrefix, rule.ID)
			f.runNetsh(ctx, "advfirewall", "firewall", "delete", "rule", fmt.Sprintf("name=%s", ruleName))
			f.runNetsh(ctx, "advfirewall", "firewall", "delete", "rule", fmt.Sprintf("name=%s-In", ruleName))
			f.runNetsh(ctx, "advfirewall", "firewall", "delete", "rule", fmt.Sprintf("name=%s-Out", ruleName))
			delete(f.rules, id)
			rulesFlushed++
		}
	}

	f.logger("flushed: rules=%d, blocks=%d", rulesFlushed, blocksFlushed)
	return rulesFlushed, blocksFlushed, nil
}

func (f *WindowsFirewall) OpenPort(ctx context.Context, port int, protocol string, direction string, sourceIP string, description string) (*sdk.FirewallRule, error) {
	if protocol == "" {
		protocol = "tcp"
	}
	if direction == "" {
		direction = "inbound"
	}

	rule := &sdk.FirewallRule{
		Name:        fmt.Sprintf("Open Port %d/%s", port, protocol),
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

func (f *WindowsFirewall) ClosePort(ctx context.Context, port int, protocol string, direction string) error {
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

			ruleName := fmt.Sprintf("%s%s", rulePrefix, rule.ID)
			f.runNetsh(ctx, "advfirewall", "firewall", "delete", "rule", fmt.Sprintf("name=%s", ruleName))
			f.runNetsh(ctx, "advfirewall", "firewall", "delete", "rule", fmt.Sprintf("name=%s-In", ruleName))
			f.runNetsh(ctx, "advfirewall", "firewall", "delete", "rule", fmt.Sprintf("name=%s-Out", ruleName))

			delete(f.rules, id)
			f.logger("closed port %d/%s", port, protocol)
			return nil
		}
	}

	return nil
}

func (f *WindowsFirewall) runNetsh(ctx context.Context, args ...string) error {
	cmd := exec.CommandContext(ctx, "netsh", args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("netsh %v: %w (output: %s)", args, err, string(output))
	}
	return nil
}

func main() {
	sdk.ServeFirewallPlugin(&WindowsFirewall{})
}
