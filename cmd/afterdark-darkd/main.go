package main

import (
	"context"
	"fmt"
	"os"

	"github.com/afterdarksys/afterdark-darkd/internal/daemon"
	"github.com/afterdarksys/afterdark-darkd/pkg/logging"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

var (
	// Version information (set by ldflags during build)
	Version   = "dev"
	Commit    = "unknown"
	BuildTime = "unknown"
)

var (
	configPath string
	logLevel   string
)

func main() {
	rootCmd := &cobra.Command{
		Use:   "afterdark-darkd",
		Short: "AfterDark endpoint security daemon",
		Long: `AfterDark-DarkD is an enterprise-grade endpoint security daemon
that provides patch compliance monitoring, threat intelligence integration,
and baseline security assessments across macOS, Windows, and Linux systems.`,
		Version: fmt.Sprintf("%s (commit: %s, built: %s)", Version, Commit, BuildTime),
		RunE:    runDaemon,
	}

	rootCmd.PersistentFlags().StringVarP(&configPath, "config", "c", "/etc/afterdark/darkd.yaml", "path to configuration file")
	rootCmd.PersistentFlags().StringVarP(&logLevel, "log-level", "l", "info", "log level (debug, info, warn, error)")

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func runDaemon(cmd *cobra.Command, args []string) error {
	// Initialize logging
	logCfg := &logging.Config{
		Level:      logging.Level(logLevel),
		Format:     "json",
		OutputPath: "stdout",
	}
	if err := logging.Init(logCfg); err != nil {
		return fmt.Errorf("failed to initialize logging: %w", err)
	}
	defer logging.Sync()

	logger := logging.Get()
	logger.Info("starting afterdark-darkd",
		zap.String("version", Version),
		zap.String("commit", Commit),
		zap.String("build_time", BuildTime),
	)

	// Load configuration
	cfg, err := daemon.LoadConfig(configPath)
	if err != nil {
		logger.Error("failed to load configuration", zap.Error(err))
		return fmt.Errorf("failed to load configuration: %w", err)
	}

	// Create daemon
	d, err := daemon.New(cfg)
	if err != nil {
		logger.Error("failed to create daemon", zap.Error(err))
		return fmt.Errorf("failed to create daemon: %w", err)
	}

	// Run daemon
	ctx := context.Background()
	if err := d.Run(ctx); err != nil {
		logger.Error("daemon error", zap.Error(err))
		return err
	}

	logger.Info("daemon shutdown complete")
	return nil
}
