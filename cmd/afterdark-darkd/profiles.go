package main

import (
	"fmt"
	"github.com/afterdarksys/afterdark-darkd/internal/models"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
	"runtime"
)

func profileCmd() *cobra.Command {
	platform := runtime.GOOS
	cmd := &cobra.Command{Use: "profile", Short: "Print a server or desktop configuration without starting services", RunE: func(cmd *cobra.Command, args []string) error {
		if deploymentMode != "server" && deploymentMode != "desktop" {
			return fmt.Errorf("choose --mode server or --mode desktop")
		}
		cfg, err := models.DefaultConfigForMode(deploymentMode, platform)
		if err != nil {
			return err
		}
		raw, err := yaml.Marshal(cfg)
		if err != nil {
			return err
		}
		_, err = cmd.OutOrStdout().Write(raw)
		return err
	}}
	cmd.Flags().StringVar(&platform, "platform", platform, "target platform: linux, darwin or windows")
	return cmd
}
