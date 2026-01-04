// Linux Firewall Plugin for afterdark-darkd
//
// Provides firewall management via nftables (preferred) or iptables (fallback).
// Supports IP blocking, rule management, and integration with threat intelligence.
//
// Build: go build -o firewall-linux .
// Install: cp firewall-linux /var/lib/afterdark-darkd/plugins/
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
	backendNftables = "nftables"
	backendIptables = "iptables"

	// nftables table and chain names
	nftTable        = "afterdark"
	nftChainInput   = "input"
	nftChainOutput  = "output"
	nftChainForward = "forward"
	nftSetBlocked   = "blocked_ips"
)

// LinuxFirewall implements the FirewallPlugin interface for Linux
type LinuxFirewall struct {
	sdk.BaseFirewallPlugin

	mu           sync.RWMutex
	backend      string
	backendVer   string
	enabled      bool
	rules        map[string]*sdk.FirewallRule
	blockedIPs   map[string]*sdk.BlockedIP
	defaultDenyIn  bool
	defaultDenyOut bool
	logger       func(string, ...interface{})
}

func (f *LinuxFirewall) Info() sdk.PluginInfo {
	return sdk.PluginInfo{
		Name:        "firewall-linux",
		Version:     "1.0.0",
		Type:        sdk.PluginTypeFirewall,
		Description: "Linux firewall plugin using nftables/iptables",
		Author:      "After Dark Systems, LLC",
		License:     "MIT",
		Capabilities: []string{
			"block_ip", "unblock_ip", "list_blocked",
			"add_rule", "remove_rule", "list_rules",
			"sync_blocklist", "open_port", "close_port",
			"nftables", "iptables",
		},
	}
}

func (f *LinuxFirewall) Configure(config map[string]interface{}) error {
	if err := f.BaseFirewallPlugin.Configure(config); err != nil {
		return err
	}

	f.mu.Lock()
	defer f.mu.Unlock()

	f.rules = make(map[string]*sdk.FirewallRule)
	f.blockedIPs = make(map[string]*sdk.BlockedIP)
	f.logger = func(format string, args ...interface{}) {
		// Default logger - plugins can override
		fmt.Printf("[firewall-linux] "+format+"\n", args...)
	}

	// Detect available backend
	if err := f.detectBackend(); err != nil {
		return fmt.Errorf("no firewall backend available: %w", err)
	}

	f.SetState(sdk.PluginStateReady, fmt.Sprintf("using %s", f.backend))
	return nil
}

func (f *LinuxFirewall) detectBackend() error {
	// Try nftables first (preferred)
	if path, err := exec.LookPath("nft"); err == nil {
		out, err := exec.Command(path, "--version").Output()
		if err == nil {
			f.backend = backendNftables
			f.backendVer = strings.TrimSpace(string(out))
			return nil
		}
	}

	// Fall back to iptables
	if path, err := exec.LookPath("iptables"); err == nil {
		out, err := exec.Command(path, "--version").Output()
		if err == nil {
			f.backend = backendIptables
			f.backendVer = strings.TrimSpace(string(out))
			return nil
		}
	}

	return fmt.Errorf("neither nftables nor iptables found")
}

func (f *LinuxFirewall) Enable(ctx context.Context, enable bool, defaultDenyInbound bool, defaultDenyOutbound bool) (*sdk.FirewallStatus, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	if enable {
		if err := f.initFirewall(ctx); err != nil {
			return nil, fmt.Errorf("failed to initialize firewall: %w", err)
		}

		if defaultDenyInbound {
			if err := f.setDefaultPolicy(ctx, "input", "drop"); err != nil {
				return nil, err
			}
		}
		if defaultDenyOutbound {
			if err := f.setDefaultPolicy(ctx, "output", "drop"); err != nil {
				return nil, err
			}
		}
	} else {
		if err := f.disableFirewall(ctx); err != nil {
			return nil, err
		}
	}

	f.enabled = enable
	f.defaultDenyIn = defaultDenyInbound
	f.defaultDenyOut = defaultDenyOutbound

	return f.getStatusLocked(), nil
}

func (f *LinuxFirewall) initFirewall(ctx context.Context) error {
	if f.backend == backendNftables {
		return f.initNftables(ctx)
	}
	return f.initIptables(ctx)
}

func (f *LinuxFirewall) initNftables(ctx context.Context) error {
	// Create table and chains
	cmds := []string{
		fmt.Sprintf("add table inet %s", nftTable),
		fmt.Sprintf("add chain inet %s %s { type filter hook input priority 0; policy accept; }", nftTable, nftChainInput),
		fmt.Sprintf("add chain inet %s %s { type filter hook output priority 0; policy accept; }", nftTable, nftChainOutput),
		fmt.Sprintf("add chain inet %s %s { type filter hook forward priority 0; policy accept; }", nftTable, nftChainForward),
		fmt.Sprintf("add set inet %s %s { type ipv4_addr; flags interval; }", nftTable, nftSetBlocked),
		fmt.Sprintf("add set inet %s %s_v6 { type ipv6_addr; flags interval; }", nftTable, nftSetBlocked),
		// Add drop rules for blocked IPs
		fmt.Sprintf("add rule inet %s %s ip saddr @%s drop", nftTable, nftChainInput, nftSetBlocked),
		fmt.Sprintf("add rule inet %s %s ip daddr @%s drop", nftTable, nftChainOutput, nftSetBlocked),
		fmt.Sprintf("add rule inet %s %s ip6 saddr @%s_v6 drop", nftTable, nftChainInput, nftSetBlocked),
		fmt.Sprintf("add rule inet %s %s ip6 daddr @%s_v6 drop", nftTable, nftChainOutput, nftSetBlocked),
	}

	for _, cmd := range cmds {
		if err := f.runNft(ctx, cmd); err != nil {
			// Ignore "already exists" errors
			if !strings.Contains(err.Error(), "File exists") {
				f.logger("nft command failed (continuing): %s - %v", cmd, err)
			}
		}
	}

	return nil
}

func (f *LinuxFirewall) initIptables(ctx context.Context) error {
	// Create custom chain for afterdark
	cmds := [][]string{
		{"-N", "AFTERDARK_INPUT"},
		{"-N", "AFTERDARK_OUTPUT"},
		{"-I", "INPUT", "-j", "AFTERDARK_INPUT"},
		{"-I", "OUTPUT", "-j", "AFTERDARK_OUTPUT"},
	}

	for _, args := range cmds {
		if err := f.runIptables(ctx, args...); err != nil {
			// Ignore chain exists errors
			if !strings.Contains(err.Error(), "Chain already exists") {
				f.logger("iptables command failed (continuing): %v - %v", args, err)
			}
		}
	}

	return nil
}

func (f *LinuxFirewall) disableFirewall(ctx context.Context) error {
	if f.backend == backendNftables {
		return f.runNft(ctx, fmt.Sprintf("delete table inet %s", nftTable))
	}

	// iptables cleanup
	cmds := [][]string{
		{"-D", "INPUT", "-j", "AFTERDARK_INPUT"},
		{"-D", "OUTPUT", "-j", "AFTERDARK_OUTPUT"},
		{"-F", "AFTERDARK_INPUT"},
		{"-F", "AFTERDARK_OUTPUT"},
		{"-X", "AFTERDARK_INPUT"},
		{"-X", "AFTERDARK_OUTPUT"},
	}

	for _, args := range cmds {
		f.runIptables(ctx, args...) // Ignore errors during cleanup
	}

	return nil
}

func (f *LinuxFirewall) setDefaultPolicy(ctx context.Context, chain string, policy string) error {
	if f.backend == backendNftables {
		return f.runNft(ctx, fmt.Sprintf("chain inet %s %s { policy %s; }", nftTable, chain, policy))
	}

	chainName := strings.ToUpper(chain)
	policyName := strings.ToUpper(policy)
	return f.runIptables(ctx, "-P", chainName, policyName)
}

func (f *LinuxFirewall) Status(ctx context.Context) (*sdk.FirewallStatus, error) {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return f.getStatusLocked(), nil
}

func (f *LinuxFirewall) getStatusLocked() *sdk.FirewallStatus {
	activeRules := 0
	for _, r := range f.rules {
		if r.Enabled {
			activeRules++
		}
	}

	return &sdk.FirewallStatus{
		Enabled:             f.enabled,
		Backend:             f.backend,
		Version:             f.backendVer,
		TotalRules:          len(f.rules),
		ActiveRules:         activeRules,
		BlockedIPs:          len(f.blockedIPs),
		DefaultDenyInbound:  f.defaultDenyIn,
		DefaultDenyOutbound: f.defaultDenyOut,
		LastUpdated:         time.Now(),
		Capabilities: map[string]string{
			"ipv4":     "true",
			"ipv6":     "true",
			"sets":     strconv.FormatBool(f.backend == backendNftables),
			"logging":  "true",
			"stateful": "true",
		},
	}
}

func (f *LinuxFirewall) BlockIP(ctx context.Context, ip string, reason string, sourceService string, durationSeconds int64, threatScore int, categories []string) (*sdk.BlockedIP, error) {
	// Validate IP
	if net.ParseIP(ip) == nil {
		_, _, err := net.ParseCIDR(ip)
		if err != nil {
			return nil, fmt.Errorf("invalid IP address: %s", ip)
		}
	}

	f.mu.Lock()
	defer f.mu.Unlock()

	// Check if already blocked
	if existing, ok := f.blockedIPs[ip]; ok {
		return existing, nil
	}

	// Add to firewall
	if err := f.blockIPLocked(ctx, ip); err != nil {
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
	f.logger("blocked IP %s (reason: %s, source: %s)", ip, reason, sourceService)

	return blocked, nil
}

func (f *LinuxFirewall) blockIPLocked(ctx context.Context, ip string) error {
	isIPv6 := strings.Contains(ip, ":")

	if f.backend == backendNftables {
		setName := nftSetBlocked
		if isIPv6 {
			setName = nftSetBlocked + "_v6"
		}
		return f.runNft(ctx, fmt.Sprintf("add element inet %s %s { %s }", nftTable, setName, ip))
	}

	// iptables
	ipver := "-A"
	if isIPv6 {
		return f.runIp6tables(ctx, ipver, "AFTERDARK_INPUT", "-s", ip, "-j", "DROP")
	}
	return f.runIptables(ctx, ipver, "AFTERDARK_INPUT", "-s", ip, "-j", "DROP")
}

func (f *LinuxFirewall) UnblockIP(ctx context.Context, ip string) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	if _, ok := f.blockedIPs[ip]; !ok {
		return nil // Not blocked
	}

	if err := f.unblockIPLocked(ctx, ip); err != nil {
		return err
	}

	delete(f.blockedIPs, ip)
	f.logger("unblocked IP %s", ip)

	return nil
}

func (f *LinuxFirewall) unblockIPLocked(ctx context.Context, ip string) error {
	isIPv6 := strings.Contains(ip, ":")

	if f.backend == backendNftables {
		setName := nftSetBlocked
		if isIPv6 {
			setName = nftSetBlocked + "_v6"
		}
		return f.runNft(ctx, fmt.Sprintf("delete element inet %s %s { %s }", nftTable, setName, ip))
	}

	// iptables
	if isIPv6 {
		return f.runIp6tables(ctx, "-D", "AFTERDARK_INPUT", "-s", ip, "-j", "DROP")
	}
	return f.runIptables(ctx, "-D", "AFTERDARK_INPUT", "-s", ip, "-j", "DROP")
}

func (f *LinuxFirewall) ListBlockedIPs(ctx context.Context, limit int, offset int, sourceService string) ([]sdk.BlockedIP, int, error) {
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

	// Apply pagination
	if offset > len(result) {
		return []sdk.BlockedIP{}, total, nil
	}
	result = result[offset:]
	if limit > 0 && len(result) > limit {
		result = result[:limit]
	}

	return result, total, nil
}

func (f *LinuxFirewall) IsIPBlocked(ctx context.Context, ip string) (bool, *sdk.BlockedIP, error) {
	f.mu.RLock()
	defer f.mu.RUnlock()

	if blocked, ok := f.blockedIPs[ip]; ok {
		return true, blocked, nil
	}
	return false, nil, nil
}

func (f *LinuxFirewall) AddRule(ctx context.Context, rule *sdk.FirewallRule) (*sdk.FirewallRule, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	// Generate ID if not provided
	if rule.ID == "" {
		rule.ID = uuid.New().String()[:8]
	}
	rule.CreatedAt = time.Now()

	// Apply rule to firewall
	if rule.Enabled {
		if err := f.applyRuleLocked(ctx, rule); err != nil {
			return nil, err
		}
	}

	f.rules[rule.ID] = rule
	f.logger("added rule %s: %s %s %s/%s -> %s/%s",
		rule.ID, rule.Action, rule.Protocol,
		rule.SourceIP, rule.SourcePort,
		rule.DestIP, rule.DestPort)

	return rule, nil
}

func (f *LinuxFirewall) applyRuleLocked(ctx context.Context, rule *sdk.FirewallRule) error {
	if f.backend == backendNftables {
		return f.applyRuleNftables(ctx, rule)
	}
	return f.applyRuleIptables(ctx, rule)
}

func (f *LinuxFirewall) applyRuleNftables(ctx context.Context, rule *sdk.FirewallRule) error {
	chain := nftChainInput
	if rule.Direction == "outbound" {
		chain = nftChainOutput
	}

	// Build rule string
	var parts []string
	parts = append(parts, fmt.Sprintf("add rule inet %s %s", nftTable, chain))

	if rule.Protocol != "" && rule.Protocol != "any" {
		parts = append(parts, fmt.Sprintf("meta l4proto %s", rule.Protocol))
	}

	if rule.SourceIP != "" && rule.SourceIP != "any" {
		if strings.Contains(rule.SourceIP, ":") {
			parts = append(parts, fmt.Sprintf("ip6 saddr %s", rule.SourceIP))
		} else {
			parts = append(parts, fmt.Sprintf("ip saddr %s", rule.SourceIP))
		}
	}

	if rule.SourcePort != "" && rule.SourcePort != "any" {
		parts = append(parts, fmt.Sprintf("%s sport %s", rule.Protocol, rule.SourcePort))
	}

	if rule.DestIP != "" && rule.DestIP != "any" {
		if strings.Contains(rule.DestIP, ":") {
			parts = append(parts, fmt.Sprintf("ip6 daddr %s", rule.DestIP))
		} else {
			parts = append(parts, fmt.Sprintf("ip daddr %s", rule.DestIP))
		}
	}

	if rule.DestPort != "" && rule.DestPort != "any" {
		parts = append(parts, fmt.Sprintf("%s dport %s", rule.Protocol, rule.DestPort))
	}

	// Add comment
	parts = append(parts, fmt.Sprintf("comment \"afterdark:%s\"", rule.ID))

	// Action
	action := rule.Action
	if action == "deny" {
		action = "drop"
	}
	parts = append(parts, action)

	return f.runNft(ctx, strings.Join(parts, " "))
}

func (f *LinuxFirewall) applyRuleIptables(ctx context.Context, rule *sdk.FirewallRule) error {
	chain := "AFTERDARK_INPUT"
	if rule.Direction == "outbound" {
		chain = "AFTERDARK_OUTPUT"
	}

	var args []string
	args = append(args, "-A", chain)

	if rule.Protocol != "" && rule.Protocol != "any" {
		args = append(args, "-p", rule.Protocol)
	}

	if rule.SourceIP != "" && rule.SourceIP != "any" {
		args = append(args, "-s", rule.SourceIP)
	}

	if rule.SourcePort != "" && rule.SourcePort != "any" {
		args = append(args, "--sport", rule.SourcePort)
	}

	if rule.DestIP != "" && rule.DestIP != "any" {
		args = append(args, "-d", rule.DestIP)
	}

	if rule.DestPort != "" && rule.DestPort != "any" {
		args = append(args, "--dport", rule.DestPort)
	}

	// Comment
	args = append(args, "-m", "comment", "--comment", fmt.Sprintf("afterdark:%s", rule.ID))

	// Action
	action := strings.ToUpper(rule.Action)
	if action == "DENY" {
		action = "DROP"
	}
	args = append(args, "-j", action)

	return f.runIptables(ctx, args...)
}

func (f *LinuxFirewall) RemoveRule(ctx context.Context, ruleID string) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	rule, ok := f.rules[ruleID]
	if !ok {
		return fmt.Errorf("rule not found: %s", ruleID)
	}

	if err := f.removeRuleLocked(ctx, rule); err != nil {
		return err
	}

	delete(f.rules, ruleID)
	f.logger("removed rule %s", ruleID)

	return nil
}

func (f *LinuxFirewall) removeRuleLocked(ctx context.Context, rule *sdk.FirewallRule) error {
	if f.backend == backendNftables {
		// Find and delete rule by comment
		chain := nftChainInput
		if rule.Direction == "outbound" {
			chain = nftChainOutput
		}

		// List rules to find handle
		out, err := exec.CommandContext(ctx, "nft", "-a", "list", "chain", "inet", nftTable, chain).Output()
		if err != nil {
			return err
		}

		// Find rule with our comment
		lines := strings.Split(string(out), "\n")
		for _, line := range lines {
			if strings.Contains(line, fmt.Sprintf("afterdark:%s", rule.ID)) {
				// Extract handle number
				parts := strings.Split(line, "handle ")
				if len(parts) >= 2 {
					handle := strings.TrimSpace(parts[1])
					return f.runNft(ctx, fmt.Sprintf("delete rule inet %s %s handle %s", nftTable, chain, handle))
				}
			}
		}
		return nil
	}

	// iptables - find and delete by comment
	chain := "AFTERDARK_INPUT"
	if rule.Direction == "outbound" {
		chain = "AFTERDARK_OUTPUT"
	}

	return f.runIptables(ctx, "-D", chain, "-m", "comment", "--comment", fmt.Sprintf("afterdark:%s", rule.ID))
}

func (f *LinuxFirewall) UpdateRule(ctx context.Context, rule *sdk.FirewallRule) (*sdk.FirewallRule, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	existing, ok := f.rules[rule.ID]
	if !ok {
		return nil, fmt.Errorf("rule not found: %s", rule.ID)
	}

	// Remove old rule
	if existing.Enabled {
		if err := f.removeRuleLocked(ctx, existing); err != nil {
			f.logger("warning: failed to remove old rule: %v", err)
		}
	}

	// Apply new rule
	if rule.Enabled {
		if err := f.applyRuleLocked(ctx, rule); err != nil {
			return nil, err
		}
	}

	f.rules[rule.ID] = rule
	return rule, nil
}

func (f *LinuxFirewall) ListRules(ctx context.Context, limit int, offset int, direction string, enabledOnly bool) ([]sdk.FirewallRule, int, error) {
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

func (f *LinuxFirewall) GetRule(ctx context.Context, ruleID string) (*sdk.FirewallRule, error) {
	f.mu.RLock()
	defer f.mu.RUnlock()

	rule, ok := f.rules[ruleID]
	if !ok {
		return nil, fmt.Errorf("rule not found: %s", ruleID)
	}
	return rule, nil
}

func (f *LinuxFirewall) SyncBlocklist(ctx context.Context, blockedIPs []sdk.BlockedIP, replace bool) (added int, removed int, unchanged int, err error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	newIPs := make(map[string]*sdk.BlockedIP)
	for i := range blockedIPs {
		newIPs[blockedIPs[i].IP] = &blockedIPs[i]
	}

	if replace {
		// Remove IPs not in new list
		for ip := range f.blockedIPs {
			if _, ok := newIPs[ip]; !ok {
				if err := f.unblockIPLocked(ctx, ip); err != nil {
					f.logger("warning: failed to unblock %s: %v", ip, err)
				}
				delete(f.blockedIPs, ip)
				removed++
			}
		}
	}

	// Add new IPs
	for ip, blocked := range newIPs {
		if _, ok := f.blockedIPs[ip]; ok {
			unchanged++
			continue
		}

		if err := f.blockIPLocked(ctx, ip); err != nil {
			f.logger("warning: failed to block %s: %v", ip, err)
			continue
		}

		blocked.BlockedAt = time.Now()
		f.blockedIPs[ip] = blocked
		added++
	}

	f.logger("blocklist sync: added=%d, removed=%d, unchanged=%d", added, removed, unchanged)
	return added, removed, unchanged, nil
}

func (f *LinuxFirewall) FlushRules(ctx context.Context, flushBlocks bool, flushRules bool, keepEssential bool) (rulesFlushed int, blocksFlushed int, err error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	if flushBlocks {
		// Clear blocked IPs
		if f.backend == backendNftables {
			f.runNft(ctx, fmt.Sprintf("flush set inet %s %s", nftTable, nftSetBlocked))
			f.runNft(ctx, fmt.Sprintf("flush set inet %s %s_v6", nftTable, nftSetBlocked))
		} else {
			f.runIptables(ctx, "-F", "AFTERDARK_INPUT")
		}
		blocksFlushed = len(f.blockedIPs)
		f.blockedIPs = make(map[string]*sdk.BlockedIP)
	}

	if flushRules {
		if f.backend == backendNftables {
			// Flush chains but keep structure
			f.runNft(ctx, fmt.Sprintf("flush chain inet %s %s", nftTable, nftChainInput))
			f.runNft(ctx, fmt.Sprintf("flush chain inet %s %s", nftTable, nftChainOutput))

			if !flushBlocks {
				// Re-add blocked IP rules
				f.runNft(ctx, fmt.Sprintf("add rule inet %s %s ip saddr @%s drop", nftTable, nftChainInput, nftSetBlocked))
				f.runNft(ctx, fmt.Sprintf("add rule inet %s %s ip daddr @%s drop", nftTable, nftChainOutput, nftSetBlocked))
			}
		} else {
			f.runIptables(ctx, "-F", "AFTERDARK_INPUT")
			f.runIptables(ctx, "-F", "AFTERDARK_OUTPUT")
		}
		rulesFlushed = len(f.rules)
		f.rules = make(map[string]*sdk.FirewallRule)
	}

	f.logger("flushed: rules=%d, blocks=%d", rulesFlushed, blocksFlushed)
	return rulesFlushed, blocksFlushed, nil
}

func (f *LinuxFirewall) OpenPort(ctx context.Context, port int, protocol string, direction string, sourceIP string, description string) (*sdk.FirewallRule, error) {
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

func (f *LinuxFirewall) ClosePort(ctx context.Context, port int, protocol string, direction string) error {
	if protocol == "" {
		protocol = "tcp"
	}
	if direction == "" {
		direction = "inbound"
	}

	f.mu.Lock()
	defer f.mu.Unlock()

	// Find matching rule
	for id, rule := range f.rules {
		if rule.DestPort == strconv.Itoa(port) &&
			rule.Protocol == protocol &&
			rule.Direction == direction &&
			rule.Action == "allow" {

			if err := f.removeRuleLocked(ctx, rule); err != nil {
				return err
			}
			delete(f.rules, id)
			f.logger("closed port %d/%s", port, protocol)
			return nil
		}
	}

	return nil // Not found, nothing to do
}

// Helper functions

func (f *LinuxFirewall) runNft(ctx context.Context, cmd string) error {
	args := strings.Fields(cmd)
	c := exec.CommandContext(ctx, "nft", args...)
	output, err := c.CombinedOutput()
	if err != nil {
		return fmt.Errorf("nft %s: %w (output: %s)", cmd, err, string(output))
	}
	return nil
}

func (f *LinuxFirewall) runIptables(ctx context.Context, args ...string) error {
	c := exec.CommandContext(ctx, "iptables", args...)
	output, err := c.CombinedOutput()
	if err != nil {
		return fmt.Errorf("iptables %v: %w (output: %s)", args, err, string(output))
	}
	return nil
}

func (f *LinuxFirewall) runIp6tables(ctx context.Context, args ...string) error {
	c := exec.CommandContext(ctx, "ip6tables", args...)
	output, err := c.CombinedOutput()
	if err != nil {
		return fmt.Errorf("ip6tables %v: %w (output: %s)", args, err, string(output))
	}
	return nil
}

func main() {
	sdk.ServeFirewallPlugin(&LinuxFirewall{})
}
