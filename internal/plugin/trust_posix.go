//go:build !windows

package plugin

import (
	"fmt"
	"os"
	"syscall"
)

func validatePluginOwner(path string, info os.FileInfo) error {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != 0 {
		return fmt.Errorf("plugin must be owned by root")
	}
	return nil
}
