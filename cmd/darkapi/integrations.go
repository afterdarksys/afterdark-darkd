package main

import (
	"context"
	"encoding/json"
	"os"
	"time"

	"github.com/afterdarksys/afterdark-darkd/internal/api/ecosystem"
	"github.com/spf13/cobra"
)

func integrationsCmd() *cobra.Command {
	root := &cobra.Command{Use: "integrations", Short: "Query verified ecosystem API contracts (credentials from provider-specific environment variables)"}
	for _, spec := range ecosystem.Contracts {
		spec := spec
		var base string
		var timeout time.Duration
		takesTarget := spec.Operation == "domain" || spec.Operation == "dns" || spec.Operation == "ip-blacklist"
		use := spec.Provider
		args := cobra.NoArgs
		if takesTarget {
			use += " TARGET"
			args = cobra.ExactArgs(1)
		}
		cmd := &cobra.Command{Use: use, Short: spec.Operation + "; credential: " + spec.CredentialEnv, Args: args, RunE: func(cmd *cobra.Command, args []string) error {
			c, err := ecosystem.New(spec.Provider, base, os.Getenv(spec.CredentialEnv), timeout)
			if err != nil {
				return err
			}
			target := ""
			if len(args) > 0 {
				target = args[0]
			}
			ctx, cancel := context.WithTimeout(cmd.Context(), timeout)
			defer cancel()
			result, err := c.Query(ctx, spec.Operation, target)
			if err != nil {
				return err
			}
			out := json.NewEncoder(cmd.OutOrStdout())
			out.SetIndent("", "  ")
			return out.Encode(result)
		}}
		cmd.Flags().StringVar(&base, "endpoint", spec.DefaultURL, "provider origin URL (no path)")
		cmd.Flags().DurationVar(&timeout, "request-timeout", 30*time.Second, "overall request timeout (maximum 2m)")
		root.AddCommand(cmd)
	}
	return root
}
