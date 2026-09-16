package endpointreport

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"strings"
	"testing"
)

func TestFirewallFixtures(t *testing.T) {
	for _, test := range []struct {
		platform, output, state string
		enabled                 *bool
	}{
		{"darwin", "Firewall is enabled. (State = 1)", "running", ptr(true)},
		{"linux", "Status: inactive", "running", ptr(false)},
		{"windows", `[{"Name":"Domain","Enabled":"True"},{"Name":"Private","Enabled":"True"},{"Name":"Public","Enabled":"False"}]`, "running", ptr(false)},
		{"windows", `[{"Name":"Domain","Enabled":"True"}]`, "failed", nil},
		{"windows", `[{"Enabled":"Unknown"},{"Enabled":"True"},{"Enabled":"True"}]`, "failed", nil},
	} {
		t.Run(test.platform+test.output, func(t *testing.T) {
			sensor, event := Firewall(context.Background(), test.platform, func(_ context.Context, name string, args ...string) ([]byte, error) {
				if test.platform == "windows" && !strings.Contains(strings.Join(args, " "), "ActiveStore") {
					t.Fatal("must query effective policy")
				}
				return []byte(test.output), nil
			})
			if sensor.State != test.state {
				t.Fatalf("state %s", sensor.State)
			}
			if test.enabled == nil {
				if _, ok := event.Facts["firewall_enabled"]; ok {
					t.Fatal("invented enforcement")
				}
			} else if event.Facts["firewall_enabled"] != *test.enabled {
				t.Fatal(event.Facts)
			}
		})
	}
}
func ptr(v bool) *bool { return &v }
func TestUnsupportedPermissionAndNFT(t *testing.T) {
	sensor, event := Firewall(context.Background(), "linux", func(_ context.Context, name string, args ...string) ([]byte, error) {
		if name == "ufw" {
			return nil, exec.ErrNotFound
		}
		return []byte(`{"nftables":[]}`), nil
	})
	if sensor.State != "running" || len(event.Facts) != 0 {
		t.Fatal("empty ruleset cannot establish enforcement", sensor, event)
	}
	sensor, _ = Firewall(context.Background(), "linux", func(context.Context, string, ...string) ([]byte, error) {
		return []byte("Permission denied"), errors.New("exit 1")
	})
	if sensor.State != "permission_denied" {
		t.Fatal(sensor)
	}
	sensor, _ = PatchHistory("windows", func(string, int) (string, error) { t.Fatal("unsupported collector read filesystem"); return "", nil })
	if sensor.State != "unsupported" {
		t.Fatal(sensor)
	}
	if State(os.ErrNotExist, nil) != "unsupported" {
		t.Fatal("missing source")
	}
}
func TestBoundedOutput(t *testing.T) {
	b := limitedBuffer{max: 8}
	if _, err := b.Write([]byte("12345678")); err != nil {
		t.Fatal(err)
	}
	if _, err := b.Write([]byte("9")); err == nil || len(b.b) != 8 {
		t.Fatal("unbounded output")
	}
}
