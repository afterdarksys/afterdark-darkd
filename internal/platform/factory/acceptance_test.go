package factory

import (
	"context"
	"os"
	"testing"
	"time"
)

// Explicit opt-in because inventory commands query the actual test machine.
// No patch installation, firewall, DNS or other host mutation is performed.
func TestNativeInventoryAcceptance(t *testing.T) {
	if os.Getenv("DARKD_NATIVE_ACCEPTANCE") != "1" {
		t.Skip("set DARKD_NATIVE_ACCEPTANCE=1 on an acceptance host")
	}
	p, err := New()
	if err != nil {
		t.Fatal(err)
	}
	info, err := p.GetOSInfo()
	if err != nil {
		t.Fatal(err)
	}
	if info.Name == "" || info.Architecture == "" {
		t.Fatalf("incomplete OS identity: %+v", info)
	}
	hostname, err := p.GetHostname()
	if err != nil || hostname == "" {
		t.Fatalf("hostname unavailable: %v", err)
	}
	interfaces, err := p.GetNetworkInterfaces()
	if err != nil {
		t.Fatal(err)
	}
	if len(interfaces) == 0 {
		t.Fatal("no network interfaces returned")
	}
	t.Run("installed applications", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
		defer cancel()
		apps, err := p.ListInstalledApplications(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if len(apps) == 0 {
			t.Fatal("empty installed application inventory on acceptance host")
		}
		for _, app := range apps {
			if app.Name == "" {
				t.Fatal("application missing name")
			}
		}
		t.Logf("collected %d applications", len(apps))
	})
	t.Run("installed patches", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
		defer cancel()
		patches, err := p.ListInstalledPatches(ctx)
		if err != nil {
			t.Fatal(err)
		}
		for _, patch := range patches {
			if patch.ID == "" {
				t.Fatal("patch missing identifier")
			}
		}
		t.Logf("collected %d installed patches", len(patches))
	})
}
