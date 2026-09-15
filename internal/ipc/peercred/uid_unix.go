//go:build darwin || linux

package peercred

import "os"

func CurrentUID() uint32 { return uint32(os.Getuid()) }
