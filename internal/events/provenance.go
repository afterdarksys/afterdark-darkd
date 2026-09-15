// Package events supplies collection-time provenance without inventing host facts.
package events

import (
	"context"
	"os"
	"os/exec"
	"runtime"
	"runtime/debug"
	"strings"
	"sync"
	"time"
)

var once sync.Once
var boot string

func reportBootID() string {
	once.Do(func() {
		switch runtime.GOOS {
		case "linux":
			b, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
			if err == nil {
				boot = strings.TrimSpace(string(b))
			}
		case "darwin":
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			b, err := exec.CommandContext(ctx, "/usr/sbin/sysctl", "-n", "kern.bootsessionuuid").Output()
			if err == nil {
				boot = strings.TrimSpace(string(b))
			}
		}
		if len(boot) > 128 {
			boot = ""
		}
	})
	return boot
}
func reportAgentVersion() string {
	if info, ok := debug.ReadBuildInfo(); ok {
		if info.Main.Version != "" && info.Main.Version != "(devel)" {
			return info.Main.Version
		}
		for _, setting := range info.Settings {
			if setting.Key == "vcs.revision" {
				return setting.Value
			}
		}
	}
	return "unknown"
}
