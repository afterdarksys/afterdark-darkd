package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"syscall"

	"github.com/afterdarksys/afterdark-darkd/internal/daemon"
	"github.com/afterdarksys/afterdark-darkd/internal/identity"
	"github.com/afterdarksys/afterdark-darkd/internal/models"
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
	configPath   string
	logLevel     string
	foreground   bool
	debug        bool
	remoteAccess string
)

func validateRemoteAccessMode() error {
	validModes := map[string]bool{
		"Enabled":    true,
		"Disabled":   true,
		"Restricted": true,
	}

	if !validModes[remoteAccess] {
		return fmt.Errorf("invalid remote access mode: %s (must be Enabled, Disabled, or Restricted)", remoteAccess)
	}
	return nil
}

func main() {
	rootCmd := &cobra.Command{
		Use:   "afterdark-darkd",
		Short: "AfterDark endpoint security daemon",
		Long: `AfterDark-DarkD is an enterprise-grade endpoint security daemon
that provides patch compliance monitoring, threat intelligence integration,
and baseline security assessments across macOS, Windows, and Linux systems.`,
		Version: fmt.Sprintf("%s (commit: %s, built: %s)", Version, Commit, BuildTime),
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			return validateRemoteAccessMode()
		},
	}

	rootCmd.PersistentFlags().StringVarP(&configPath, "config", "c", "/etc/afterdark/darkd.yaml", "path to configuration file")
	rootCmd.PersistentFlags().StringVarP(&logLevel, "log-level", "l", "info", "log level (debug, info, warn, error)")
	rootCmd.PersistentFlags().StringVar(&remoteAccess, "remote", "Enabled", "remote access mode (Enabled, Disabled, Restricted)")

	// Add subcommands
	rootCmd.AddCommand(runCmd())
	rootCmd.AddCommand(daemonizeCmd())
	rootCmd.AddCommand(foregroundCmd())
	rootCmd.AddCommand(debugCmd())
	rootCmd.AddCommand(statusCmd())
	rootCmd.AddCommand(stopCmd())
	rootCmd.AddCommand(restartCmd())
	rootCmd.AddCommand(logsCmd())
	rootCmd.AddCommand(configCmd())
	rootCmd.AddCommand(serviceCmd())
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
		RunE:  runService,
	}
}

func daemonizeCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "daemonize",
		Short: "Run as a background daemon",
		Long:  "Start the daemon in the background with proper signal handling and PID file management.",
		RunE:  runService,
	}
}

func foregroundCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "foreground",
		Short: "Run in foreground mode",
		Long:  "Run the daemon in the foreground with console output. Useful for debugging and container deployments.",
		RunE: func(cmd *cobra.Command, args []string) error {
			foreground = true
			return runService(cmd, args)
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
			return runService(cmd, args)
		},
	}
}

func statusCmd() *cobra.Command {
	var verbose bool

	cmd := &cobra.Command{
		Use:   "status",
		Short: "Show daemon status",
		RunE: func(cmd *cobra.Command, args []string) error {
			// Check remote access mode - if Restricted, return minimal info only
			if remoteAccess == "Restricted" {
				fmt.Println("Status: Restricted")
				return nil
			}

			// If Disabled, show limited info
			if remoteAccess == "Disabled" {
				fmt.Println("Remote access: Disabled")
				fmt.Println("Local status information is unavailable in remote mode")
				return nil
			}

			// Full status (Enabled mode)
			fmt.Println("AfterDark-DarkD Status")
			fmt.Println("======================")
			fmt.Printf("Remote Access: %s\n", remoteAccess)
			fmt.Println()

			// Check if daemon is running
			pidFile := "/var/run/afterdark/darkd.pid"
			running := false
			var pid string

			if _, err := os.Stat(pidFile); err == nil {
				data, err := os.ReadFile(pidFile)
				if err == nil {
					pid = string(data)
					running = true
				}
			}

			// Status
			if running {
				fmt.Printf("● Daemon: \033[32mrunning\033[0m (PID: %s)\n", pid)
			} else {
				fmt.Printf("● Daemon: \033[31mstopped\033[0m\n")
			}

			// Version
			fmt.Printf("  Version: %s\n", Version)
			fmt.Printf("  Commit:  %s\n", Commit)
			fmt.Printf("  Built:   %s\n", BuildTime)
			fmt.Println()

			// Config file
			fmt.Printf("Configuration\n")
			fmt.Printf("  File: %s\n", configPath)
			if _, err := os.Stat(configPath); err == nil {
				fmt.Printf("  Exists: \033[32myes\033[0m\n")
			} else {
				fmt.Printf("  Exists: \033[31mno\033[0m\n")
			}
			fmt.Println()

			// Show system identity
			fmt.Printf("System Identity\n")
			id, err := identity.LoadIdentity()
			if err == nil && id != nil {
				fmt.Printf("  System ID: %s\n", id.SystemID)
				fmt.Printf("  Hostname:  %s\n", id.Hostname)
				fmt.Printf("  OS/Arch:   %s/%s\n", id.OS, id.Arch)
				if id.Registered {
					fmt.Printf("  Status:    \033[32mregistered\033[0m (%s)\n", id.AccountEmail)
				} else {
					fmt.Printf("  Status:    \033[33mnot registered\033[0m\n")
				}
			} else {
				fmt.Printf("  Status: \033[31mnot generated\033[0m\n")
				fmt.Printf("  Run: afterdark-darkd generate-system-id\n")
			}
			fmt.Println()

			// Check service status
			if verbose {
				fmt.Printf("System Service\n")
				if _, err := exec.LookPath("systemctl"); err == nil {
					cmd := exec.Command("systemctl", "is-enabled", "afterdark-darkd")
					if output, err := cmd.Output(); err == nil {
						fmt.Printf("  Systemd: %s\n", string(output))
					} else {
						fmt.Printf("  Systemd: not installed\n")
					}
				} else if _, err := exec.LookPath("launchctl"); err == nil {
					plistPath := "/Library/LaunchDaemons/com.afterdark.darkd.plist"
					if _, err := os.Stat(plistPath); err == nil {
						fmt.Printf("  Launchd: installed\n")
					} else {
						fmt.Printf("  Launchd: not installed\n")
					}
				}
				fmt.Println()
			}

			fmt.Println("Commands:")
			fmt.Println("  afterdark-darkd start     - Start the daemon")
			fmt.Println("  afterdark-darkd stop      - Stop the daemon")
			fmt.Println("  afterdark-darkd restart   - Restart the daemon")
			fmt.Println("  afterdark-darkd logs -f   - Follow daemon logs")

			return nil
		},
	}

	cmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "show detailed status")

	return cmd
}

func apiCmd() *cobra.Command {
	var port string

	cmd := &cobra.Command{
		Use:   "api",
		Short: "API server mode",
		Long:  "Run only the API server without the full daemon services.",
	}

	startCmd := &cobra.Command{
		Use:   "start",
		Short: "Start API server only",
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Printf("Starting API server on %s...\n", port)

			// Set API mode flag
			os.Setenv("AFTERDARK_API_MODE", "true")
			os.Setenv("AFTERDARK_API_PORT", port)

			return runService(cmd, args)
		},
	}

	startCmd.Flags().StringVarP(&port, "port", "p", ":8080", "TCP port to listen on")
	cmd.AddCommand(startCmd)

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
			// Restrict in Restricted mode
			if remoteAccess == "Restricted" {
				fmt.Println("Status: Restricted")
				return nil
			}
			if remoteAccess == "Disabled" {
				return fmt.Errorf("machine information unavailable: remote access is disabled")
			}
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

func stopCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "stop",
		Short: "Stop the daemon",
		Long:  "Stop the running daemon gracefully by sending SIGTERM signal.",
		RunE: func(cmd *cobra.Command, args []string) error {
			pidFile := "/var/run/afterdark/darkd.pid"

			if _, err := os.Stat(pidFile); os.IsNotExist(err) {
				fmt.Println("Daemon is not running")
				return nil
			}

			data, err := os.ReadFile(pidFile)
			if err != nil {
				return fmt.Errorf("failed to read PID file: %w", err)
			}

			var pid int
			if _, err := fmt.Sscanf(string(data), "%d", &pid); err != nil {
				return fmt.Errorf("invalid PID file: %w", err)
			}

			process, err := os.FindProcess(pid)
			if err != nil {
				return fmt.Errorf("failed to find process: %w", err)
			}

			fmt.Printf("Stopping daemon (PID: %d)...\n", pid)
			if err := process.Signal(syscall.SIGTERM); err != nil {
				return fmt.Errorf("failed to send signal: %w", err)
			}

			fmt.Println("Daemon stopped successfully")
			return nil
		},
	}
}

func restartCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "restart",
		Short: "Restart the daemon",
		Long:  "Stop and start the daemon.",
		RunE: func(cmd *cobra.Command, args []string) error {
			// Stop first
			stopCommand := stopCmd()
			if err := stopCommand.RunE(cmd, args); err != nil {
				fmt.Printf("Warning: stop failed: %v\n", err)
			}

			// Wait a moment
			fmt.Println("Waiting for daemon to stop...")
			// In production, should poll for process to actually stop

			// Start
			fmt.Println("Starting daemon...")
			return runService(cmd, args)
		},
	}
}

func logsCmd() *cobra.Command {
	var follow bool
	var lines int

	cmd := &cobra.Command{
		Use:   "logs",
		Short: "View daemon logs",
		Long:  "Display logs from the running daemon.",
		RunE: func(cmd *cobra.Command, args []string) error {
			// Restrict logs in Restricted or Disabled mode
			if remoteAccess == "Restricted" {
				fmt.Println("Status: Restricted")
				return nil
			}
			if remoteAccess == "Disabled" {
				return fmt.Errorf("logs unavailable: remote access is disabled")
			}
			logFile := "/var/log/afterdark/darkd.log"

			if _, err := os.Stat(logFile); os.IsNotExist(err) {
				fmt.Println("Log file not found. Daemon may not be running.")
				return nil
			}

			if follow {
				// Use tail -f
				tailCmd := exec.Command("tail", "-f", "-n", fmt.Sprintf("%d", lines), logFile)
				tailCmd.Stdout = os.Stdout
				tailCmd.Stderr = os.Stderr
				return tailCmd.Run()
			}

			// Just show last N lines
			tailCmd := exec.Command("tail", "-n", fmt.Sprintf("%d", lines), logFile)
			output, err := tailCmd.Output()
			if err != nil {
				return fmt.Errorf("failed to read logs: %w", err)
			}
			fmt.Print(string(output))
			return nil
		},
	}

	cmd.Flags().BoolVarP(&follow, "follow", "f", false, "follow log output")
	cmd.Flags().IntVarP(&lines, "lines", "n", 50, "number of lines to show")

	return cmd
}

func configCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "config",
		Short: "Manage configuration",
		Long:  "View and modify daemon configuration.",
	}

	cmd.AddCommand(&cobra.Command{
		Use:   "show",
		Short: "Show current configuration",
		RunE: func(cmd *cobra.Command, args []string) error {
			// Restrict config viewing in Restricted or Disabled mode
			if remoteAccess == "Restricted" {
				fmt.Println("Status: Restricted")
				return nil
			}
			if remoteAccess == "Disabled" {
				return fmt.Errorf("configuration unavailable: remote access is disabled")
			}

			data, err := os.ReadFile(configPath)
			if err != nil {
				return fmt.Errorf("failed to read config: %w", err)
			}
			fmt.Print(string(data))
			return nil
		},
	})

	cmd.AddCommand(&cobra.Command{
		Use:   "path",
		Short: "Show configuration file path",
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Println(configPath)
			return nil
		},
	})

	cmd.AddCommand(&cobra.Command{
		Use:   "validate",
		Short: "Validate configuration file",
		RunE: func(cmd *cobra.Command, args []string) error {
			_, err := daemon.LoadConfig(configPath)
			if err != nil {
				fmt.Printf("Configuration is invalid: %v\n", err)
				return err
			}
			fmt.Println("Configuration is valid")
			return nil
		},
	})

	return cmd
}

func serviceCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "service",
		Short: "Manage system service",
		Long:  "Install, uninstall, enable, or disable the system service (systemd/launchd).",
	}

	cmd.AddCommand(&cobra.Command{
		Use:   "install",
		Short: "Install system service",
		RunE: func(cmd *cobra.Command, args []string) error {
			return installSystemService()
		},
	})

	cmd.AddCommand(&cobra.Command{
		Use:   "uninstall",
		Short: "Uninstall system service",
		RunE: func(cmd *cobra.Command, args []string) error {
			return uninstallSystemService()
		},
	})

	cmd.AddCommand(&cobra.Command{
		Use:   "enable",
		Short: "Enable service to start on boot",
		RunE: func(cmd *cobra.Command, args []string) error {
			return enableSystemService()
		},
	})

	cmd.AddCommand(&cobra.Command{
		Use:   "disable",
		Short: "Disable service from starting on boot",
		RunE: func(cmd *cobra.Command, args []string) error {
			return disableSystemService()
		},
	})

	return cmd
}

func installSystemService() error {
	if _, err := exec.LookPath("systemctl"); err == nil {
		return installSystemdService()
	} else if _, err := exec.LookPath("launchctl"); err == nil {
		return installLaunchdService()
	}
	return fmt.Errorf("no supported service manager found (systemd/launchd)")
}

func installSystemdService() error {
	serviceContent := `[Unit]
Description=AfterDark Endpoint Security Daemon
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/afterdark-darkd run
Restart=on-failure
RestartSec=5
User=root

[Install]
WantedBy=multi-user.target
`
	servicePath := "/etc/systemd/system/afterdark-darkd.service"
	if err := os.WriteFile(servicePath, []byte(serviceContent), 0644); err != nil {
		return fmt.Errorf("failed to write service file: %w", err)
	}

	cmd := exec.Command("systemctl", "daemon-reload")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to reload systemd: %w", err)
	}

	fmt.Println("Systemd service installed successfully")
	fmt.Println("Run 'afterdark-darkd service enable' to enable auto-start on boot")
	return nil
}

func installLaunchdService() error {
	plistContent := `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Label</key>
	<string>com.afterdark.darkd</string>
	<key>ProgramArguments</key>
	<array>
		<string>/usr/local/bin/afterdark-darkd</string>
		<string>run</string>
	</array>
	<key>RunAtLoad</key>
	<true/>
	<key>KeepAlive</key>
	<true/>
	<key>StandardErrorPath</key>
	<string>/var/log/afterdark/darkd.log</string>
	<key>StandardOutPath</key>
	<string>/var/log/afterdark/darkd.log</string>
</dict>
</plist>
`
	plistPath := "/Library/LaunchDaemons/com.afterdark.darkd.plist"
	if err := os.WriteFile(plistPath, []byte(plistContent), 0644); err != nil {
		return fmt.Errorf("failed to write plist file: %w", err)
	}

	// Ensure log directory exists
	if err := os.MkdirAll("/var/log/afterdark", 0755); err != nil {
		return fmt.Errorf("failed to create log directory: %w", err)
	}

	fmt.Println("Launchd service installed successfully")
	fmt.Println("Run 'afterdark-darkd service enable' to load the service")
	return nil
}

func uninstallSystemService() error {
	if _, err := exec.LookPath("systemctl"); err == nil {
		servicePath := "/etc/systemd/system/afterdark-darkd.service"
		exec.Command("systemctl", "stop", "afterdark-darkd").Run()
		exec.Command("systemctl", "disable", "afterdark-darkd").Run()
		os.Remove(servicePath)
		exec.Command("systemctl", "daemon-reload").Run()
		fmt.Println("Systemd service uninstalled")
		return nil
	} else if _, err := exec.LookPath("launchctl"); err == nil {
		plistPath := "/Library/LaunchDaemons/com.afterdark.darkd.plist"
		exec.Command("launchctl", "unload", plistPath).Run()
		os.Remove(plistPath)
		fmt.Println("Launchd service uninstalled")
		return nil
	}
	return fmt.Errorf("no supported service manager found")
}

func enableSystemService() error {
	if _, err := exec.LookPath("systemctl"); err == nil {
		cmd := exec.Command("systemctl", "enable", "afterdark-darkd")
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("failed to enable service: %w", err)
		}
		cmd = exec.Command("systemctl", "start", "afterdark-darkd")
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("failed to start service: %w", err)
		}
		fmt.Println("Service enabled and started")
		return nil
	} else if _, err := exec.LookPath("launchctl"); err == nil {
		plistPath := "/Library/LaunchDaemons/com.afterdark.darkd.plist"
		cmd := exec.Command("launchctl", "load", "-w", plistPath)
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("failed to load service: %w", err)
		}
		fmt.Println("Service enabled and loaded")
		return nil
	}
	return fmt.Errorf("no supported service manager found")
}

func disableSystemService() error {
	if _, err := exec.LookPath("systemctl"); err == nil {
		exec.Command("systemctl", "stop", "afterdark-darkd").Run()
		cmd := exec.Command("systemctl", "disable", "afterdark-darkd")
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("failed to disable service: %w", err)
		}
		fmt.Println("Service disabled")
		return nil
	} else if _, err := exec.LookPath("launchctl"); err == nil {
		plistPath := "/Library/LaunchDaemons/com.afterdark.darkd.plist"
		cmd := exec.Command("launchctl", "unload", plistPath)
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("failed to unload service: %w", err)
		}
		fmt.Println("Service disabled")
		return nil
	}
	return fmt.Errorf("no supported service manager found")
}

// runService is defined in service_posix.go and service_windows.go

func runDaemon(cmd *cobra.Command, args []string) error {
	// Setup signal handling
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)

	go func() {
		for sig := range sigChan {
			switch sig {
			case syscall.SIGHUP:
				logging.Get().Info("received SIGHUP, reloading configuration")
				// Reload config (implementation pending)
			case syscall.SIGINT, syscall.SIGTERM:
				logging.Get().Info("received shutdown signal", zap.String("signal", sig.String()))
				cancel()
				return
			}
		}
	}()

	return runDaemonWithContext(ctx)
}

func runDaemonWithContext(ctx context.Context) error {
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

	// Check for API mode override
	if os.Getenv("AFTERDARK_API_MODE") == "true" {
		logger.Info("Starting in API-only mode")

		// Disable all services
		cfg.Services = models.ServicesConfig{} // Empty struct disables all

		// Set TCP Address
		port := os.Getenv("AFTERDARK_API_PORT")
		if port == "" {
			port = ":8080"
		}
		cfg.IPC.TCPAddr = port

		// Ensure socket path is valid or empty if conflicting
		// Keep socket path for local admin tool access if wanted, but fine to keep defaults
	}

	// Create daemon
	d, err := daemon.New(cfg)
	if err != nil {
		logger.Error("failed to create daemon", zap.Error(err))
		return fmt.Errorf("failed to create daemon: %w", err)
	}

	// Run daemon
	if err := d.Run(ctx); err != nil {
		logger.Error("daemon error", zap.Error(err))
		return err
	}

	logger.Info("daemon shutdown complete")
	return nil
}
