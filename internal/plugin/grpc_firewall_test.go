package plugin

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"testing"
	"time"

	sdk "github.com/afterdarksys/afterdark-darkd/pkg/pluginsdk"
	goplugin "github.com/hashicorp/go-plugin"
)

// Unused methods deliberately panic through the embedded interface: this fixture
// only implements the protocol operations exercised below.
type fixtureFirewall struct {
	sdk.FirewallPlugin
	sdk.BaseFirewallPlugin
}

func (*fixtureFirewall) Info() sdk.PluginInfo {
	return sdk.PluginInfo{Name: "fixture-firewall", Type: sdk.PluginTypeFirewall, Version: "1"}
}
func (f *fixtureFirewall) Configure(c map[string]interface{}) error {
	return f.BaseFirewallPlugin.Configure(c)
}
func (f *fixtureFirewall) Health() sdk.PluginHealth { return f.BaseFirewallPlugin.Health() }
func (*fixtureFirewall) Status(context.Context) (*sdk.FirewallStatus, error) {
	return &sdk.FirewallStatus{Backend: "fixture", Enabled: true}, nil
}
func (*fixtureFirewall) BlockIP(_ context.Context, ip, reason, source string, duration int64, score int, categories []string) (*sdk.BlockedIP, error) {
	if ip == "invalid" {
		return nil, fmt.Errorf("invalid address")
	}
	return &sdk.BlockedIP{IP: ip, Reason: reason, SourceService: source, ThreatScore: score, Categories: categories, BlockedAt: time.Unix(100, 0), ExpiresAt: time.Unix(100+duration, 0)}, nil
}
func TestFirewallPluginHelper(t *testing.T) {
	if os.Getenv("DARKD_FIREWALL_HELPER") != "1" {
		return
	}
	sdk.ServeFirewallPlugin(&fixtureFirewall{})
	os.Exit(0)
}
func TestFirewallSDKNegotiation(t *testing.T) {
	cmd := exec.Command(os.Args[0], "-test.run=^TestFirewallPluginHelper$")
	cmd.Env = append(os.Environ(), "DARKD_FIREWALL_HELPER=1")
	client := goplugin.NewClient(&goplugin.ClientConfig{HandshakeConfig: HandshakeConfig, Plugins: PluginMap, Cmd: cmd, AllowedProtocols: []goplugin.Protocol{goplugin.ProtocolGRPC}, StartTimeout: 10 * time.Second})
	defer client.Kill()
	protocol, err := client.Client()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := (&Host{}).dispensePlugin(protocol)
	if err != nil {
		t.Fatal(err)
	}
	firewall, ok := raw.(FirewallPlugin)
	if !ok {
		t.Fatalf("wrong adapter: %T", raw)
	}
	info, err := (&Host{}).getPluginInfo(raw)
	if err != nil || info.Type != PluginTypeFirewall {
		t.Fatalf("info=%+v error=%v", info, err)
	}
	if err := firewall.Configure(map[string]interface{}{"dry_run": true}); err != nil {
		t.Fatal(err)
	}
	if h := firewall.Health(); h.State != PluginStateReady {
		t.Fatalf("health=%+v", h)
	}
	state, err := firewall.Status(context.Background())
	if err != nil || state.Backend != "fixture" {
		t.Fatalf("status=%+v error=%v", state, err)
	}
	blocked, err := firewall.BlockIP(context.Background(), "192.0.2.1", "test", "review", 60, 80, []string{"test"})
	if err != nil || blocked.IP != "192.0.2.1" || blocked.ExpiresAt.Unix() != 160 || blocked.ThreatScore != 80 {
		t.Fatalf("block=%+v error=%v", blocked, err)
	}
	if _, err := firewall.BlockIP(context.Background(), "invalid", "", "", 1, 0, nil); err == nil {
		t.Fatal("server rejection hidden")
	}
	if _, err := firewall.Enable(context.Background(), true, true, false); err == nil {
		t.Fatal("default deny accepted without rollback")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := firewall.Status(ctx); err == nil {
		t.Fatal("cancellation ignored")
	}
}
func TestRejectUntrustedPluginBeforeLaunch(t *testing.T) {
	path := t.TempDir() + "/plugin"
	if err := os.WriteFile(path, []byte("not executable"), 0666); err != nil {
		t.Fatal(err)
	}
	if _, err := (&Host{}).LoadPlugin(path); err == nil {
		t.Fatal("untrusted plugin accepted")
	}
}
