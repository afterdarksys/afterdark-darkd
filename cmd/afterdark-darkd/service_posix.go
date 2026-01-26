//go:build !windows

package main

import "github.com/spf13/cobra"

// runService maps to runDaemon on POSIX systems
func runService(cmd *cobra.Command, args []string) error {
	return runDaemon(cmd, args)
}
