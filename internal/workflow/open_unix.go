//go:build !windows

package workflow

import "syscall"

const nonblock = syscall.O_NONBLOCK
