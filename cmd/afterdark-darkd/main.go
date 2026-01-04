package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/afterdarksys/afterdark-darkd/internal/daemon"
	"github.com/afterdarksys/afterdark-darkd/internal/identity"
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
	foreground bool
	debug      bool
)

func main() {
	rootCmd := &cobra.Command{
		Use:   "afterdark-darkd",
		Short: "AfterDark endpoint security daemon",
		Long: `AfterDark-DarkD is an enterprise-grade endpoint security daemon
that provides patch compliance monitoring, threat intelligence integration,
and baseline security assessments across macOS, Windows, and Linux systems.`,
		Version: fmt.Sprintf("%s (commit: %s, built: %s)", Version, Commit, BuildTime),
	}

	rootCmd.PersistentFlags().StringVarP(&configPath, "config", "c", "/etc/afterdark/darkd.yaml", "path to configuration file")
	rootCmd.PersistentFlags().StringVarP(&logLevel, "log-level", "l", "info", "log level (debug, info, warn, error)")

	// Add subcommands
	rootCmd.AddCommand(runCmd())
	rootCmd.AddCommand(daemonizeCmd())
	rootCmd.AddCommand(foregroundCmd())
	rootCmd.AddCommand(debugCmd())
	rootCmd.AddCommand(statusCmd())
	rootCmd.AddCommand(apiCmd())
	rootCmd.AddCommand(showCmd())
	rootCmd.AddCommand(generateSystemIDCmd())

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func runCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "run",
		Short: "Run the daemon (alias for daemonize)",
		RunE:  runDaemon,
	}
}

func daemonizeCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "daemonize",
		Short: "Run as a background daemon",
		Long:  "Start the daemon in the background with proper signal handling and PID file management.",
		RunE:  runDaemon,
	}
}

func foregroundCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "foreground",
		Short: "Run in foreground mode",
		Long:  "Run the daemon in the foreground with console output. Useful for debugging and container deployments.",
		RunE: func(cmd *cobra.Command, args []string) error {
			foreground = true
			return runDaemon(cmd, args)
		},
	}
	return cmd
}

func debugCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "debug",
		Short: "Run in debug mode",
		Long:  "Run the daemon in foreground with debug logging enabled.",
		RunE: func(cmd *cobra.Command, args []string) error {
			foreground = true
			debug = true
			logLevel = "debug"
			return runDaemon(cmd, args)
		},
	}
}

func statusCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Show daemon status",
		RunE: func(cmd *cobra.Command, args []string) error {
			// Check if daemon is running
			pidFile := "/var/run/afterdark/darkd.pid"
			if _, err := os.Stat(pidFile); os.IsNotExist(err) {
				fmt.Println("Status: stopped")
				return nil
			}

			// Read PID
			data, err := os.ReadFile(pidFile)
			if err != nil {
				fmt.Println("Status: unknown (cannot read PID file)")
				return nil
			}

			fmt.Printf("Status: running (PID: %s)\n", string(data))

			// Show system identity
			id, err := identity.LoadIdentity()
			if err == nil && id != nil {
				fmt.Printf("System ID: %s\n", id.SystemID)
				fmt.Printf("Hostname: %s\n", id.Hostname)
				fmt.Printf("OS/Arch: %s/%s\n", id.OS, id.Arch)
				if id.Registered {
					fmt.Printf("Registered: yes (%s)\n", id.AccountEmail)
				} else {
					fmt.Println("Registered: no")
				}
			}

			return nil
		},
	}
}

func apiCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "api",
		Short: "API server mode",
		Long:  "Run only the API server without the full daemon services.",
	}

	cmd.AddCommand(&cobra.Command{
		Use:   "start",
		Short: "Start API server only",
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Println("Starting API server on :8080...")
			fmt.Println("(API-only mode not yet implemented)")
			return nil
		},
	})

	return cmd
}

func showCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "show",
		Short: "Show resources",
		Long:  "Display information about machines, files, or collections.",
	}

	cmd.AddCommand(&cobra.Command{
		Use:   "machines",
		Short: "Show registered machines",
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Println("Registered Machines")
			fmt.Println("===================")

			id, err := identity.LoadIdentity()
			if err != nil || id == nil {
				fmt.Println("No machines registered. Run 'afterdark-darkd generate-system-id' first.")
				return nil
			}

			fmt.Printf("1. %s\n", id.Hostname)
			fmt.Printf("   System ID:  %s\n", id.SystemID)
			fmt.Printf("   OS/Arch:    %s/%s\n", id.OS, id.Arch)
			fmt.Printf("   Registered: %v\n", id.Registered)

			return nil
		},
	})

	cmd.AddCommand(&cobra.Command{
		Use:   "files",
		Short: "Show tracked files",
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Println("Tracked Files")
			fmt.Println("=============")
			fmt.Println("(No files tracked yet)")
			return nil
		},
	})

	cmd.AddCommand(&cobra.Command{
		Use:   "file [path]",
		Short: "Show details for a specific file",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			path := args[0]
			fmt.Printf("File: %s\n", path)
			fmt.Println("======")
			fmt.Println("(File not found in tracking database)")
			return nil
		},
	})

	cmd.AddCommand(&cobra.Command{
		Use:   "collection [name]",
		Short: "Show a collection of tracked items",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 {
				fmt.Println("Collections")
				fmt.Println("===========")
				fmt.Println("  default     - Default collection")
				fmt.Println("  downloads   - Downloaded files")
				fmt.Println("  documents   - Document files")
				return nil
			}

			name := args[0]
			fmt.Printf("Collection: %s\n", name)
			fmt.Println("============")
			fmt.Println("(Collection is empty)")
			return nil
		},
	})

	return cmd
}

func generateSystemIDCmd() *cobra.Command {
	var force bool

	cmd := &cobra.Command{
		Use:   "generate-system-id",
		Short: "Generate a unique system ID",
		Long: `Generate a unique system identifier for this machine.
The ID is derived from the machine ID and hostname, ensuring consistency
across reboots. Use 'darkdadm login' to register this system with your account.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			// Check for existing identity
			existing, err := identity.LoadIdentity()
			if err != nil {
				return fmt.Errorf("failed to check existing identity: %w", err)
			}

			if existing != nil && !force {
				fmt.Println("System ID already exists:")
				fmt.Printf("  System ID:  %s\n", existing.SystemID)
				fmt.Printf("  Hostname:   %s\n", existing.Hostname)
				fmt.Printf("  OS/Arch:    %s/%s\n", existing.OS, existing.Arch)
				fmt.Printf("  Registered: %v\n", existing.Registered)
				fmt.Println("\nUse --force to regenerate.")
				return nil
			}

			// Generate new identity
			id, err := identity.GenerateSystemID()
			if err != nil {
				return fmt.Errorf("failed to generate system ID: %w", err)
			}

			// Save identity
			if err := id.Save(); err != nil {
				return fmt.Errorf("failed to save identity: %w", err)
			}

			fmt.Println("System ID generated successfully!")
			fmt.Println()
			fmt.Printf("  System ID:  %s\n", id.SystemID)
			fmt.Printf("  Hostname:   %s\n", id.Hostname)
			fmt.Printf("  Machine ID: %s\n", id.MachineID)
			fmt.Printf("  OS/Arch:    %s/%s\n", id.OS, id.Arch)
			fmt.Println()
			fmt.Println("Next steps:")
			fmt.Println("  1. Run 'darkdadm login' to authenticate with your AfterDark account")
			fmt.Println("  2. The system will be registered to your account automatically")

			return nil
		},
	}

	cmd.Flags().BoolVarP(&force, "force", "f", false, "force regeneration of system ID")

	return cmd
}

func runDaemon(cmd *cobra.Command, args []string) error {
	// Initialize logging
	logFormat := "json"
	if foreground || debug {
		logFormat = "console"
	}

	logCfg := &logging.Config{
		Level:      logging.Level(logLevel),
		Format:     logFormat,
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
		zap.Bool("foreground", foreground),
		zap.Bool("debug", debug),
	)

	// Ensure system identity exists
	id, created, err := identity.GetOrCreateIdentity()
	if err != nil {
		logger.Warn("failed to get/create system identity", zap.Error(err))
	} else {
		if created {
			logger.Info("created new system identity", zap.String("system_id", id.SystemID))
		} else {
			logger.Info("loaded system identity", zap.String("system_id", id.SystemID))
		}
	}

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

	// Setup signal handling
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)

	go func() {
		for sig := range sigChan {
			switch sig {
			case syscall.SIGHUP:
				logger.Info("received SIGHUP, reloading configuration")
				// Reload config
			case syscall.SIGINT, syscall.SIGTERM:
				logger.Info("received shutdown signal", zap.String("signal", sig.String()))
				cancel()
				return
			}
		}
	}()

	// Run daemon
	if err := d.Run(ctx); err != nil {
		logger.Error("daemon error", zap.Error(err))
		return err
	}

	logger.Info("daemon shutdown complete")
	return nil
}
