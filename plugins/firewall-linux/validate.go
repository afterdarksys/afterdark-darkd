package main

import (
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"

	sdk "github.com/afterdarksys/afterdark-darkd/pkg/pluginsdk"
)

var safeRuleID = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)

func validateFirewallRule(rule *sdk.FirewallRule) error {
	if rule == nil {
		return fmt.Errorf("firewall rule is required")
	}
	if rule.ID != "" && !safeRuleID.MatchString(rule.ID) {
		return fmt.Errorf("invalid firewall rule ID")
	}
	if rule.Direction != "inbound" && rule.Direction != "outbound" && rule.Direction != "both" {
		return fmt.Errorf("invalid firewall direction")
	}
	if rule.Action != "allow" && rule.Action != "deny" && rule.Action != "drop" && rule.Action != "reject" {
		return fmt.Errorf("invalid firewall action")
	}
	if rule.Protocol != "" && rule.Protocol != "any" && rule.Protocol != "tcp" && rule.Protocol != "udp" && rule.Protocol != "icmp" {
		return fmt.Errorf("invalid firewall protocol")
	}
	if rule.Protocol == "icmp" && (hasPort(rule.SourcePort) || hasPort(rule.DestPort)) {
		return fmt.Errorf("ICMP rules cannot specify ports")
	}
	if err := validateFirewallAddress(rule.SourceIP); err != nil {
		return fmt.Errorf("source IP: %w", err)
	}
	if err := validateFirewallAddress(rule.DestIP); err != nil {
		return fmt.Errorf("destination IP: %w", err)
	}
	if err := validateFirewallPort(rule.SourcePort); err != nil {
		return fmt.Errorf("source port: %w", err)
	}
	if err := validateFirewallPort(rule.DestPort); err != nil {
		return fmt.Errorf("destination port: %w", err)
	}
	return nil
}

func validateFirewallAddress(value string) error {
	if value != strings.TrimSpace(value) {
		return fmt.Errorf("whitespace is not allowed")
	}
	if value == "" || value == "any" {
		return nil
	}
	if ip := net.ParseIP(value); ip != nil {
		return nil
	}
	if _, _, err := net.ParseCIDR(value); err != nil {
		return fmt.Errorf("must be an IP or CIDR")
	}
	return nil
}

func hasPort(value string) bool {
	return strings.TrimSpace(value) != "" && strings.TrimSpace(value) != "any"
}

func validateFirewallPort(value string) error {
	if value != strings.TrimSpace(value) {
		return fmt.Errorf("whitespace is not allowed")
	}
	if value == "" || value == "any" {
		return nil
	}
	parts := strings.Split(value, "-")
	if len(parts) > 2 || parts[0] == "" {
		return fmt.Errorf("must be a port or port range")
	}
	start, err := strconv.Atoi(parts[0])
	if err != nil || start < 1 || start > 65535 {
		return fmt.Errorf("invalid port")
	}
	if len(parts) == 2 {
		end, err := strconv.Atoi(parts[1])
		if err != nil || end < start || end > 65535 {
			return fmt.Errorf("invalid port range")
		}
	}
	return nil
}
