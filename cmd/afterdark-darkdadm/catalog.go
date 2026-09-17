package main

import (
	"encoding/json"
	"fmt"
	"github.com/afterdarksys/afterdark-darkd/internal/plugin"
	"github.com/spf13/cobra"
)

func catalogCommands(root *cobra.Command) {
	for _, action := range []string{"catalog", "install"} {
		action := action
		var url, key, destination string
		cmd := &cobra.Command{Use: action, Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, args []string) error {
			catalog, err := plugin.FetchCatalog(cmd.Context(), url, key)
			if err != nil {
				return err
			}
			if action == "catalog" {
				return json.NewEncoder(cmd.OutOrStdout()).Encode(catalog.Digests)
			}
			if err := catalog.Install(cmd.Context(), args[0], destination, key); err != nil {
				return err
			}
			fmt.Fprintln(cmd.OutOrStdout(), "Verified plugin staged in", destination, "; enable signature enforcement with the trusted publisher key before activation.")
			return nil
		}}
		cmd.Flags().StringVar(&url, "url", "", "platform-specific HTTPS catalog directory")
		cmd.Flags().StringVar(&key, "public-key", "", "trusted publisher Ed25519 public key (base64)")
		cmd.MarkFlagRequired("url")
		cmd.MarkFlagRequired("public-key")
		if action == "install" {
			cmd.Use = "install <name>"
			cmd.Args = cobra.ExactArgs(1)
			cmd.Flags().StringVar(&destination, "destination", "", "new versioned plugin directory")
			cmd.MarkFlagRequired("destination")
		}
		root.AddCommand(cmd)
	}
}
