package main

import "testing"

func TestRejectFirewallWhitespaceAndInjection(t *testing.T) {
	for _, value := range []string{" 127.0.0.1", "127.0.0.1\n", "any\npass all", "--help"} {
		if err := validateFirewallAddress(value); err == nil {
			t.Fatalf("accepted address %q", value)
		}
	}
	for _, value := range []string{" 443", "443\n", "80;accept", "0", "65536", "443-80"} {
		if err := validateFirewallPort(value); err == nil {
			t.Fatalf("accepted port %q", value)
		}
	}
	for _, value := range []string{"443", "80-443", "any"} {
		if err := validateFirewallPort(value); err != nil {
			t.Fatalf("rejected port %q: %v", value, err)
		}
	}
}
