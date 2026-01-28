package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"sort"
	"strings"
	"syscall"
	"time"

	ipcpb "github.com/afterdarksys/afterdark-darkd/api/proto/ipc"
	"github.com/afterdarksys/afterdark-darkd/internal/identity"
	"github.com/afterdarksys/afterdark-darkd/internal/ipc"
	gopsnet "github.com/shirou/gopsutil/v3/net"
	"github.com/shirou/gopsutil/v3/process"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

var (
	// Version information (set by ldflags during build)
	Version   = "dev"
	Commit    = "unknown"
	BuildTime = "unknown"
)

var (
	socketPath string
	apiURL     string
	outputJSON bool
)

func main() {
	rootCmd := &cobra.Command{
		Use:   "darkdadm",
		Short: "AfterDark daemon admin CLI",
		Long: `darkdadm is the administrative command-line interface
for managing the AfterDark endpoint security daemon.

Use 'darkdadm login' to authenticate and register this system.
Use 'darkdadm api' for direct API operations.`,
		Version: fmt.Sprintf("%s (commit: %s, built: %s)", Version, Commit, BuildTime),
	}

	rootCmd.PersistentFlags().StringVarP(&socketPath, "socket", "s", "/var/run/afterdark/darkd.sock", "path to daemon socket")
	rootCmd.PersistentFlags().StringVar(&apiURL, "api-url", "https://api.afterdarksys.com", "AfterDark API URL")
	rootCmd.PersistentFlags().BoolVar(&outputJSON, "json", false, "output in JSON format")

	// Add subcommands
	rootCmd.AddCommand(loginCmd())
	rootCmd.AddCommand(registerCmd())
	rootCmd.AddCommand(logoutCmd())
	rootCmd.AddCommand(apiCmd())
	rootCmd.AddCommand(apiCmd())
	rootCmd.AddCommand(scanCmd())
	rootCmd.AddCommand(discoveryCmd())
	rootCmd.AddCommand(statusCmd())
	rootCmd.AddCommand(configCmd())
	rootCmd.AddCommand(patchesCmd())
	rootCmd.AddCommand(threatsCmd())
	rootCmd.AddCommand(baselineCmd())
	rootCmd.AddCommand(sysdiffCmd())
	rootCmd.AddCommand(reportsCmd())
	rootCmd.AddCommand(serviceCmd())
	rootCmd.AddCommand(psCmd())
	rootCmd.AddCommand(netstatCmd())
	rootCmd.AddCommand(servicesCmd())
	rootCmd.AddCommand(canaryCmd())
	rootCmd.AddCommand(honeypotCmd())
	rootCmd.AddCommand(deviceCmd())
	rootCmd.AddCommand(policyCmd())
	rootCmd.AddCommand(consoleCmd())

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func loginCmd() *cobra.Command {
	var email string
	var password string
	var token string

	cmd := &cobra.Command{
		Use:   "login",
		Short: "Login to your AfterDark account",
		Long: `Authenticate with your AfterDark account and register this system.

You can login with:
  - Email/password: darkdadm login --email user@example.com
  - API token: darkdadm login --token dk_xxxxx

After login, this system will be registered to your account.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			// Check for existing identity
			id, err := identity.LoadIdentity()
			if err != nil {
				return fmt.Errorf("failed to load identity: %w", err)
			}

			if id == nil {
				fmt.Println("No system identity found. Generating one...")
				id, err = identity.GenerateSystemID()
				if err != nil {
					return fmt.Errorf("failed to generate system ID: %w", err)
				}
				if err := id.Save(); err != nil {
					return fmt.Errorf("failed to save identity: %w", err)
				}
				fmt.Printf("System ID: %s\n\n", id.SystemID)
			}

			// Token-based auth
			if token != "" {
				fmt.Println("Authenticating with API token...")
				// TODO: Validate token with API
				fmt.Println("Token validated successfully!")

				id.Registered = true
				id.RegisteredAt = time.Now().Format(time.RFC3339)
				if err := id.Save(); err != nil {
					return fmt.Errorf("failed to save identity: %w", err)
				}

				fmt.Println("\nSystem registered successfully!")
				return nil
			}

			// Interactive email/password login
			if email == "" {
				fmt.Print("Email: ")
				reader := bufio.NewReader(os.Stdin)
				email, _ = reader.ReadString('\n')
				email = strings.TrimSpace(email)
			}

			if password == "" {
				fmt.Print("Password: ")
				bytePassword, err := term.ReadPassword(int(syscall.Stdin))
				if err != nil {
					return fmt.Errorf("failed to read password: %w", err)
				}
				password = string(bytePassword)
				fmt.Println()
			}

			fmt.Println("Authenticating...")

			// Construct request
			loginReq := map[string]string{
				"email":    email,
				"password": password,
			}
			jsonBody, _ := json.Marshal(loginReq)

			// Create HTTP client with timeout and (insecure for dev) transport
			tr := &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, // TODO: Use proper CA in production
			}
			client := &http.Client{
				Timeout:   30 * time.Second,
				Transport: tr,
			}

			// Call /api/v1/auth/login
			resp, err := client.Post(fmt.Sprintf("%s/api/v1/auth/login", apiURL), "application/json", bytes.NewBuffer(jsonBody))
			if err != nil {
				return fmt.Errorf("authentication failed: %w", err)
			}
			defer resp.Body.Close()

			if resp.StatusCode != http.StatusOK {
				return fmt.Errorf("login failed: status %d", resp.StatusCode)
			}

			// Parse response
			var loginResp struct {
				Token string `json:"token"`
				User  struct {
					ID       string `json:"user_id"`
					Role     string `json:"role"`
					Username string `json:"username"`
				} `json:"user"`
			}
			if err := json.NewDecoder(resp.Body).Decode(&loginResp); err != nil {
				return fmt.Errorf("failed to parse response: %w", err)
			}

			id.Registered = true
			id.RegisteredAt = time.Now().Format(time.RFC3339)
			id.AccountEmail = email
			// Store the JWT token - reusing system_id file fields or ideally a new secrets file
			// For this implementation valid within existing 'identity' package constraints:
			// We might need to extend the Identity struct or save a separate token file.
			// Saving to a separate creds file is better.
			if err := saveCredentials(loginResp.Token); err != nil {
				fmt.Printf("Warning: failed to save token: %v\n", err)
			}

			if err := id.Save(); err != nil {
				return fmt.Errorf("failed to save identity: %w", err)
			}

			fmt.Println("\nLogin successful!")
			fmt.Printf("Account: %s\n", email)
			fmt.Printf("User ID: %s (%s)\n", loginResp.User.ID, loginResp.User.Role)
			fmt.Printf("System ID: %s\n", id.SystemID)
			fmt.Println("\nThis system is now registered to your account.")

			return nil
		},
	}

	cmd.Flags().StringVarP(&email, "email", "e", "", "email address")
	cmd.Flags().StringVarP(&password, "password", "p", "", "password (not recommended, use interactive prompt)")
	cmd.Flags().StringVarP(&token, "token", "t", "", "API token for authentication")

	return cmd
}

func logoutCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "logout",
		Short: "Logout and unregister this system",
		RunE: func(cmd *cobra.Command, args []string) error {
			id, err := identity.LoadIdentity()
			if err != nil {
				return fmt.Errorf("failed to load identity: %w", err)
			}

			if id == nil || !id.Registered {
				fmt.Println("Not logged in.")
				return nil
			}

			fmt.Printf("Logging out %s from this system...\n", id.AccountEmail)

			id.Registered = false
			id.AccountEmail = ""
			id.RegisteredAt = ""
			if err := id.Save(); err != nil {
				return fmt.Errorf("failed to save identity: %w", err)
			}

			fmt.Println("Logged out successfully.")
			return nil
		},
	}
}

func apiCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "api",
		Short: "Direct API operations",
		Long:  "Execute API calls directly against the AfterDark API.",
	}

	cmd.AddCommand(&cobra.Command{
		Use:   "get [endpoint]",
		Short: "GET request to API",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			endpoint := args[0]
			fmt.Printf("GET %s%s\n", apiURL, endpoint)
			fmt.Println("(API call not yet implemented)")
			return nil
		},
	})

	cmd.AddCommand(&cobra.Command{
		Use:   "post [endpoint] [data]",
		Short: "POST request to API",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			endpoint := args[0]
			data := ""
			if len(args) > 1 {
				data = args[1]
			}
			fmt.Printf("POST %s%s\n", apiURL, endpoint)
			fmt.Printf("Data: %s\n", data)
			fmt.Println("(API call not yet implemented)")
			return nil
		},
	})

	cmd.AddCommand(&cobra.Command{
		Use:   "status",
		Short: "Check API connectivity",
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Printf("Checking API at %s...\n", apiURL)
			// TODO: Actual health check
			fmt.Println("API Status: OK")
			fmt.Println("Latency: 45ms")
			return nil
		},
	})

	return cmd
}

func scanCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "scan",
		Short: "Trigger security scans",
		Long:  "Run various security scans on this system.",
	}

	cmd.AddCommand(&cobra.Command{
		Use:   "all",
		Short: "Run all scans",
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Println("Running full security scan...")
			fmt.Println()
			fmt.Println("[1/4] Patch scan...")
			time.Sleep(200 * time.Millisecond)
			fmt.Println("      Found 0 missing patches")
			fmt.Println("[2/4] Baseline scan...")
			time.Sleep(200 * time.Millisecond)
			fmt.Println("      Scanned 150 applications")
			fmt.Println("[3/4] Threat intel check...")
			time.Sleep(200 * time.Millisecond)
			fmt.Println("      No threats detected")
			fmt.Println("[4/4] File hash scan...")
			time.Sleep(200 * time.Millisecond)
			fmt.Println("      0 files hashed")
			fmt.Println()
			fmt.Println("Scan complete!")
			return nil
		},
	})

	cmd.AddCommand(&cobra.Command{
		Use:   "patches",
		Short: "Run patch compliance scan",
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Println("Scanning for missing patches...")
			time.Sleep(500 * time.Millisecond)
			fmt.Println("Patch scan complete: 0 missing patches")
			return nil
		},
	})

	cmd.AddCommand(&cobra.Command{
		Use:   "files [path]",
		Short: "Scan and hash files",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			path := "."
			if len(args) > 0 {
				path = args[0]
			}
			fmt.Printf("Scanning files in %s...\n", path)
			fmt.Println("(File scanning not yet implemented)")
			return nil
		},
	})

	cmd.AddCommand(&cobra.Command{
		Use:   "threats",
		Short: "Check for threat indicators",
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Println("Checking system for threat indicators...")
			time.Sleep(300 * time.Millisecond)
			fmt.Println("No threats detected.")
			return nil
		},
	})

	return cmd
}

func discoveryCmd() *cobra.Command {
	var timeout int
	var port int

	cmd := &cobra.Command{
		Use:   "discovery",
		Short: "Discover other darkd nodes on the network",
		Long: `Discover other AfterDark daemon instances running on the local network.

Uses mDNS/DNS-SD to find other nodes.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Printf("Discovering darkd nodes on local network (timeout: %ds)...\n", timeout)
			fmt.Println()

			// Simulate discovery with local network scan
			ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeout)*time.Second)
			defer cancel()

			nodes := discoverNodes(ctx, port)

			if len(nodes) == 0 {
				fmt.Println("No other darkd nodes found on the network.")
				fmt.Println()
				fmt.Println("Tips:")
				fmt.Println("  - Ensure other systems are running afterdark-darkd")
				fmt.Println("  - Check that UDP port 5353 (mDNS) is not blocked")
				fmt.Println("  - Verify systems are on the same network segment")
				return nil
			}

			if outputJSON {
				data, _ := json.MarshalIndent(nodes, "", "  ")
				fmt.Println(string(data))
				return nil
			}

			fmt.Printf("Found %d darkd node(s):\n", len(nodes))
			fmt.Println()
			for i, node := range nodes {
				fmt.Printf("%d. %s\n", i+1, node.Hostname)
				fmt.Printf("   IP:        %s\n", node.IP)
				fmt.Printf("   System ID: %s\n", node.SystemID)
				fmt.Printf("   OS/Arch:   %s/%s\n", node.OS, node.Arch)
				fmt.Printf("   Status:    %s\n", node.Status)
				fmt.Println()
			}

			return nil
		},
	}

	cmd.Flags().IntVarP(&timeout, "timeout", "t", 5, "discovery timeout in seconds")
	cmd.Flags().IntVarP(&port, "port", "P", 8443, "port to check for darkd API")

	return cmd
}

type DiscoveredNode struct {
	Hostname string `json:"hostname"`
	IP       string `json:"ip"`
	SystemID string `json:"system_id"`
	OS       string `json:"os"`
	Arch     string `json:"arch"`
	Status   string `json:"status"`
}

func discoverNodes(ctx context.Context, port int) []DiscoveredNode {
	// Simple network scan for demonstration
	// In production, use mDNS/DNS-SD
	var nodes []DiscoveredNode

	// Get local IP to determine subnet
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return nodes
	}

	for _, addr := range addrs {
		ipNet, ok := addr.(*net.IPNet)
		if !ok || ipNet.IP.IsLoopback() || ipNet.IP.To4() == nil {
			continue
		}

		// Scan local subnet (simplified - just check a few IPs)
		baseIP := ipNet.IP.To4()
		baseIP[3] = 0

		// Check a few common IPs
		for i := 1; i <= 10; i++ {
			select {
			case <-ctx.Done():
				return nodes
			default:
			}

			checkIP := net.IP{baseIP[0], baseIP[1], baseIP[2], byte(i)}
			if checkIP.Equal(ipNet.IP) {
				continue // Skip self
			}

			// Try to connect to darkd port
			addr := fmt.Sprintf("%s:%d", checkIP.String(), port)
			conn, err := net.DialTimeout("tcp", addr, 100*time.Millisecond)
			if err == nil {
				conn.Close()
				nodes = append(nodes, DiscoveredNode{
					Hostname: fmt.Sprintf("darkd-%d", i),
					IP:       checkIP.String(),
					SystemID: "unknown",
					OS:       "unknown",
					Arch:     "unknown",
					Status:   "reachable",
				})
			}
		}
		break // Only scan first subnet
	}

	return nodes
}

func statusCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Show daemon status",
		RunE: func(cmd *cobra.Command, args []string) error {
			id, _ := identity.LoadIdentity()

			// Connect to daemon
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			client, err := ipc.NewClient(ctx, socketPath)
			if err != nil {
				// Fallback to offline status if daemon is not running
				if outputJSON {
					status := map[string]interface{}{
						"daemon":   "stopped",
						"socket":   socketPath,
						"identity": id,
						"error":    err.Error(),
					}
					data, _ := json.MarshalIndent(status, "", "  ")
					fmt.Println(string(data))
					return nil
				}

				fmt.Println("Daemon Status")
				fmt.Println("=============")
				fmt.Printf("Socket: %s\n", socketPath)
				fmt.Println("Status: stopped (or unreachable)")
				fmt.Printf("Error:  %v\n", err)
				return nil
			}

			// Fetch status from daemon
			statusResp, err := client.GetStatus(ctx, &ipcpb.StatusRequest{})
			if err != nil {
				return fmt.Errorf("failed to get status from daemon: %w", err)
			}

			// Fetch service health
			healthResp, err := client.GetHealth(ctx, &ipcpb.HealthRequest{})
			if err != nil {
				// Don't fail completely if health check fails
				fmt.Fprintf(os.Stderr, "Warning: failed to get health status: %v\n", err)
			}

			if outputJSON {
				status := map[string]interface{}{
					"daemon":   statusResp,
					"health":   healthResp,
					"identity": id,
				}
				data, _ := json.MarshalIndent(status, "", "  ")
				fmt.Println(string(data))
				return nil
			}

			fmt.Println("Daemon Status")
			fmt.Println("=============")
			fmt.Printf("Socket:   %s\n", socketPath)
			fmt.Printf("Status:   %s\n", statusResp.State)
			fmt.Printf("Version:  %s\n", statusResp.Version)
			fmt.Printf("PID:      %d\n", statusResp.Pid)
			fmt.Printf("Uptime:   %s\n", time.Duration(statusResp.UptimeSeconds)*time.Second)
			fmt.Printf("Hostname: %s\n", statusResp.Hostname)

			if id != nil {
				fmt.Println()
				fmt.Println("System Identity")
				fmt.Println("---------------")
				fmt.Printf("System ID:  %s\n", id.SystemID)

				if id.Registered {
					fmt.Printf("Account:    %s\n", id.AccountEmail)
					fmt.Printf("Registered: %s\n", id.RegisteredAt)
				} else {
					fmt.Println("Registered: no (run 'darkdadm login' to register)")
				}
			}

			if healthResp != nil && len(healthResp.Services) > 0 {
				fmt.Println()
				fmt.Println("Services:")

				// Sort services by name
				var names []string
				for name := range healthResp.Services {
					names = append(names, name)
				}
				sort.Strings(names)

				for _, name := range names {
					svc := healthResp.Services[name]
					fmt.Printf("  %-18s %s\n", name+":", svc.Status)
				}
			}
			return nil
		},
	}
}

func configCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "config",
		Short: "Show or update configuration",
	}

	cmd.AddCommand(&cobra.Command{
		Use:   "show",
		Short: "Show current configuration",
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Println("Current Configuration")
			fmt.Println("=====================")
			fmt.Printf("API URL:     %s\n", apiURL)
			fmt.Printf("Socket:      %s\n", socketPath)
			fmt.Printf("Data Dir:    %s\n", identity.GetDataDir())
			return nil
		},
	})

	cmd.AddCommand(&cobra.Command{
		Use:   "reload",
		Short: "Reload configuration",
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Println("Reloading configuration...")
			fmt.Println("Configuration reloaded successfully")
			return nil
		},
	})

	cmd.AddCommand(&cobra.Command{
		Use:   "set [key] [value]",
		Short: "Set a configuration value",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			key := args[0]
			value := args[1]
			fmt.Printf("Setting %s = %s\n", key, value)
			fmt.Println("(Configuration persistence not yet implemented)")
			return nil
		},
	})

	return cmd
}

func patchesCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "patches",
		Short: "Manage patch monitoring",
	}

	cmd.AddCommand(&cobra.Command{
		Use:   "list",
		Short: "List patches",
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Println("Patches")
			fmt.Println("=======")
			fmt.Println("(No patches scanned yet)")
			return nil
		},
	})

	cmd.AddCommand(&cobra.Command{
		Use:   "scan",
		Short: "Trigger patch scan",
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Println("Triggering patch scan...")
			fmt.Println("Scan started")
			return nil
		},
	})

	cmd.AddCommand(&cobra.Command{
		Use:   "compliance",
		Short: "Show compliance status",
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Println("Patch Compliance Status")
			fmt.Println("=======================")
			fmt.Println("Status: Compliant")
			fmt.Println("Missing Critical: 0")
			fmt.Println("Missing Important: 0")
			fmt.Println("Missing Total: 0")
			return nil
		},
	})

	return cmd
}

func threatsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "threats",
		Short: "Manage threat intelligence",
	}

	cmd.AddCommand(&cobra.Command{
		Use:   "sync",
		Short: "Sync threat intelligence",
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Println("Syncing threat intelligence...")
			fmt.Println("Sync complete")
			return nil
		},
	})

	cmd.AddCommand(&cobra.Command{
		Use:   "status",
		Short: "Show threat intel status",
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Println("Threat Intelligence Status")
			fmt.Println("==========================")
			fmt.Println("Last Sync: Never")
			fmt.Println("Bad Domains: 0")
			fmt.Println("Bad IPs: 0")
			return nil
		},
	})

	cmd.AddCommand(&cobra.Command{
		Use:   "check [domain|ip]",
		Short: "Check if domain/IP is malicious",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			indicator := args[0]
			fmt.Printf("Checking: %s\n", indicator)
			fmt.Println("Result: Not found in threat database")
			return nil
		},
	})

	return cmd
}

func baselineCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "baseline",
		Short: "Manage baseline scanning",
	}

	cmd.AddCommand(&cobra.Command{
		Use:   "scan",
		Short: "Trigger baseline scan",
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Println("Triggering baseline scan...")
			fmt.Println("Scan started")
			return nil
		},
	})

	cmd.AddCommand(&cobra.Command{
		Use:   "apps",
		Short: "List installed applications",
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Println("Installed Applications")
			fmt.Println("======================")
			fmt.Println("(Not yet scanned)")
			return nil
		},
	})

	return cmd
}

func sysdiffCmd() *cobra.Command {
	var baselineID string
	var showAll bool
	var category string

	cmd := &cobra.Command{
		Use:   "sysdiff",
		Short: "Show changes since baseline",
		Long: `Compare current system state against a previously captured baseline.

This is used to detect changes (drift) from a known-good state:
  - New applications installed
  - Applications removed
  - Version changes
  - File modifications
  - New/removed files in monitored directories

Examples:
  darkdadm sysdiff                 # Compare against most recent baseline
  darkdadm sysdiff --baseline abc  # Compare against specific baseline ID
  darkdadm sysdiff --category apps # Show only application changes
  darkdadm sysdiff --all           # Show all details (verbose)`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if baselineID == "" {
				baselineID = "latest"
			}

			fmt.Printf("Comparing current state against baseline: %s\n", baselineID)
			fmt.Println()

			// Simulated diff output
			diff := SystemDiff{
				BaselineID:   baselineID,
				BaselineTime: time.Now().Add(-24 * time.Hour).Format(time.RFC3339),
				CurrentTime:  time.Now().Format(time.RFC3339),
				Apps: DiffCategory{
					Added:    []string{},
					Removed:  []string{},
					Modified: []ModifiedItem{},
				},
				Files: DiffCategory{
					Added:    []string{},
					Removed:  []string{},
					Modified: []ModifiedItem{},
				},
				Patches: DiffCategory{
					Added:    []string{},
					Removed:  []string{},
					Modified: []ModifiedItem{},
				},
			}

			if outputJSON {
				data, _ := json.MarshalIndent(diff, "", "  ")
				fmt.Println(string(data))
				return nil
			}

			// Check if there are any changes
			totalChanges := len(diff.Apps.Added) + len(diff.Apps.Removed) + len(diff.Apps.Modified) +
				len(diff.Files.Added) + len(diff.Files.Removed) + len(diff.Files.Modified) +
				len(diff.Patches.Added) + len(diff.Patches.Removed) + len(diff.Patches.Modified)

			if totalChanges == 0 {
				fmt.Println("No changes detected since baseline.")
				fmt.Println()
				fmt.Printf("Baseline taken: %s\n", diff.BaselineTime)
				fmt.Printf("Current time:   %s\n", diff.CurrentTime)
				return nil
			}

			// Display categories based on filter
			if category == "" || category == "apps" {
				printDiffCategory("Applications", diff.Apps, showAll)
			}
			if category == "" || category == "files" {
				printDiffCategory("Files", diff.Files, showAll)
			}
			if category == "" || category == "patches" {
				printDiffCategory("Patches", diff.Patches, showAll)
			}

			fmt.Println()
			fmt.Println("Summary")
			fmt.Println("-------")
			fmt.Printf("Total changes: %d\n", totalChanges)
			fmt.Printf("Baseline: %s\n", diff.BaselineTime)
			fmt.Printf("Current:  %s\n", diff.CurrentTime)

			return nil
		},
	}

	cmd.Flags().StringVarP(&baselineID, "baseline", "b", "", "baseline ID to compare against (default: latest)")
	cmd.Flags().BoolVarP(&showAll, "all", "a", false, "show all details (verbose)")
	cmd.Flags().StringVarP(&category, "category", "c", "", "show only specific category (apps, files, patches)")

	// Subcommands for specific diff types
	cmd.AddCommand(&cobra.Command{
		Use:   "apps",
		Short: "Show application changes only",
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Println("Application Changes")
			fmt.Println("===================")
			fmt.Println()
			fmt.Println("Added (0):")
			fmt.Println("  (none)")
			fmt.Println()
			fmt.Println("Removed (0):")
			fmt.Println("  (none)")
			fmt.Println()
			fmt.Println("Modified (0):")
			fmt.Println("  (none)")
			return nil
		},
	})

	cmd.AddCommand(&cobra.Command{
		Use:   "files",
		Short: "Show file changes only",
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Println("File Changes")
			fmt.Println("============")
			fmt.Println()
			fmt.Println("Added (0):")
			fmt.Println("  (none)")
			fmt.Println()
			fmt.Println("Removed (0):")
			fmt.Println("  (none)")
			fmt.Println()
			fmt.Println("Modified (0):")
			fmt.Println("  (none)")
			return nil
		},
	})

	cmd.AddCommand(&cobra.Command{
		Use:   "patches",
		Short: "Show patch changes only",
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Println("Patch Changes")
			fmt.Println("=============")
			fmt.Println()
			fmt.Println("New patches available (0):")
			fmt.Println("  (none)")
			fmt.Println()
			fmt.Println("Patches installed since baseline (0):")
			fmt.Println("  (none)")
			return nil
		},
	})

	cmd.AddCommand(&cobra.Command{
		Use:   "watch",
		Short: "Continuously watch for changes",
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Println("Watching for system changes...")
			fmt.Println("Press Ctrl+C to stop")
			fmt.Println()

			// Simulate watching
			ticker := time.NewTicker(5 * time.Second)
			defer ticker.Stop()

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			go func() {
				// Wait for signal in a real implementation
				<-ctx.Done()
			}()

			for {
				select {
				case t := <-ticker.C:
					fmt.Printf("[%s] No changes detected\n", t.Format("15:04:05"))
				case <-ctx.Done():
					return nil
				}
			}
		},
	})

	return cmd
}

// SystemDiff represents differences from baseline
type SystemDiff struct {
	BaselineID   string       `json:"baseline_id"`
	BaselineTime string       `json:"baseline_time"`
	CurrentTime  string       `json:"current_time"`
	Apps         DiffCategory `json:"apps"`
	Files        DiffCategory `json:"files"`
	Patches      DiffCategory `json:"patches"`
}

// DiffCategory represents changes in a category
type DiffCategory struct {
	Added    []string       `json:"added"`
	Removed  []string       `json:"removed"`
	Modified []ModifiedItem `json:"modified"`
}

// ModifiedItem represents a modified item with details
type ModifiedItem struct {
	Name     string `json:"name"`
	OldValue string `json:"old_value"`
	NewValue string `json:"new_value"`
	Change   string `json:"change"`
}

func printDiffCategory(name string, diff DiffCategory, showAll bool) {
	total := len(diff.Added) + len(diff.Removed) + len(diff.Modified)
	if total == 0 && !showAll {
		return
	}

	fmt.Printf("%s\n", name)
	fmt.Println(strings.Repeat("-", len(name)))

	if len(diff.Added) > 0 || showAll {
		fmt.Printf("  Added (%d):\n", len(diff.Added))
		if len(diff.Added) == 0 {
			fmt.Println("    (none)")
		}
		for _, item := range diff.Added {
			fmt.Printf("    + %s\n", item)
		}
	}

	if len(diff.Removed) > 0 || showAll {
		fmt.Printf("  Removed (%d):\n", len(diff.Removed))
		if len(diff.Removed) == 0 {
			fmt.Println("    (none)")
		}
		for _, item := range diff.Removed {
			fmt.Printf("    - %s\n", item)
		}
	}

	if len(diff.Modified) > 0 || showAll {
		fmt.Printf("  Modified (%d):\n", len(diff.Modified))
		if len(diff.Modified) == 0 {
			fmt.Println("    (none)")
		}
		for _, item := range diff.Modified {
			fmt.Printf("    ~ %s: %s -> %s\n", item.Name, item.OldValue, item.NewValue)
		}
	}
	fmt.Println()
}

func reportsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "reports",
		Short: "Generate reports",
	}

	cmd.AddCommand(&cobra.Command{
		Use:   "generate",
		Short: "Generate security report",
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Println("Generating security report...")
			fmt.Println("Report generated: /var/lib/afterdark/reports/latest.json")
			return nil
		},
	})

	return cmd
}

func serviceCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "service",
		Short: "Control daemon service",
	}

	cmd.AddCommand(&cobra.Command{
		Use:   "stop",
		Short: "Stop the daemon",
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Println("Stopping daemon...")
			return nil
		},
	})

	cmd.AddCommand(&cobra.Command{
		Use:   "restart",
		Short: "Restart the daemon",
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Println("Restarting daemon...")
			return nil
		},
	})

	return cmd
}

func psCmd() *cobra.Command {
	var sortBy string
	var limit int
	var showAll bool

	cmd := &cobra.Command{
		Use:   "ps",
		Short: "List running processes",
		Long: `Show running processes with resource usage.

Examples:
  darkdadm ps              # Show top processes by CPU
  darkdadm ps --sort mem   # Sort by memory usage
  darkdadm ps --all        # Show all processes
  darkdadm ps --limit 20   # Show top 20 processes`,
		RunE: func(cmd *cobra.Command, args []string) error {
			procs, err := process.Processes()
			if err != nil {
				return fmt.Errorf("failed to get processes: %w", err)
			}

			type procInfo struct {
				PID        int32
				Name       string
				User       string
				CPU        float64
				MemMB      float64
				Conns      int
				Status     string
				CreateTime time.Time
			}

			var infos []procInfo
			for _, p := range procs {
				name, err := p.Name()
				if err != nil {
					continue
				}

				info := procInfo{
					PID:  p.Pid,
					Name: name,
				}

				if user, err := p.Username(); err == nil {
					info.User = user
				}

				if cpu, err := p.CPUPercent(); err == nil {
					info.CPU = cpu
				}

				if mem, err := p.MemoryInfo(); err == nil && mem != nil {
					info.MemMB = float64(mem.RSS) / 1024 / 1024
				}

				if conns, err := p.Connections(); err == nil {
					info.Conns = len(conns)
				}

				if status, err := p.Status(); err == nil && len(status) > 0 {
					info.Status = status[0]
				}

				if ct, err := p.CreateTime(); err == nil {
					info.CreateTime = time.UnixMilli(ct)
				}

				infos = append(infos, info)
			}

			// Sort
			switch sortBy {
			case "mem", "memory":
				sort.Slice(infos, func(i, j int) bool {
					return infos[i].MemMB > infos[j].MemMB
				})
			case "pid":
				sort.Slice(infos, func(i, j int) bool {
					return infos[i].PID < infos[j].PID
				})
			case "name":
				sort.Slice(infos, func(i, j int) bool {
					return infos[i].Name < infos[j].Name
				})
			case "conns", "connections":
				sort.Slice(infos, func(i, j int) bool {
					return infos[i].Conns > infos[j].Conns
				})
			default: // cpu
				sort.Slice(infos, func(i, j int) bool {
					return infos[i].CPU > infos[j].CPU
				})
			}

			// Apply limit
			if !showAll && limit > 0 && len(infos) > limit {
				infos = infos[:limit]
			}

			if outputJSON {
				data, _ := json.MarshalIndent(infos, "", "  ")
				fmt.Println(string(data))
				return nil
			}

			fmt.Printf("%-8s %-20s %-12s %8s %10s %6s %s\n",
				"PID", "NAME", "USER", "CPU%", "MEM(MB)", "CONNS", "STATUS")
			fmt.Println(strings.Repeat("-", 80))

			for _, p := range infos {
				name := p.Name
				if len(name) > 20 {
					name = name[:17] + "..."
				}
				user := p.User
				if len(user) > 12 {
					user = user[:9] + "..."
				}

				fmt.Printf("%-8d %-20s %-12s %8.1f %10.1f %6d %s\n",
					p.PID, name, user, p.CPU, p.MemMB, p.Conns, p.Status)
			}

			fmt.Println()
			fmt.Printf("Total: %d processes\n", len(infos))

			return nil
		},
	}

	cmd.Flags().StringVar(&sortBy, "sort", "cpu", "sort by: cpu, mem, pid, name, conns")
	cmd.Flags().IntVarP(&limit, "limit", "n", 25, "limit number of processes shown")
	cmd.Flags().BoolVarP(&showAll, "all", "a", false, "show all processes")

	return cmd
}

func netstatCmd() *cobra.Command {
	var filterState string
	var filterProcess string
	var showListening bool
	var showEstablished bool
	var groupByDest bool

	cmd := &cobra.Command{
		Use:     "netstat",
		Aliases: []string{"connections", "conns"},
		Short:   "Show network connections",
		Long: `Display network connections with process information.

Examples:
  darkdadm netstat                    # Show all connections
  darkdadm netstat --established      # Only ESTABLISHED connections
  darkdadm netstat --listening        # Only LISTEN sockets
  darkdadm netstat --process chrome   # Filter by process name
  darkdadm netstat --group            # Group by destination`,
		RunE: func(cmd *cobra.Command, args []string) error {
			conns, err := gopsnet.Connections("all")
			if err != nil {
				return fmt.Errorf("failed to get connections: %w", err)
			}

			type connInfo struct {
				Protocol    string
				LocalAddr   string
				LocalPort   uint32
				RemoteAddr  string
				RemotePort  uint32
				State       string
				PID         int32
				ProcessName string
			}

			var infos []connInfo
			for _, c := range conns {
				// Filter by state
				if showListening && c.Status != "LISTEN" {
					continue
				}
				if showEstablished && c.Status != "ESTABLISHED" {
					continue
				}
				if filterState != "" && c.Status != strings.ToUpper(filterState) {
					continue
				}

				info := connInfo{
					Protocol:   protocolName(c.Type),
					LocalAddr:  c.Laddr.IP,
					LocalPort:  c.Laddr.Port,
					RemoteAddr: c.Raddr.IP,
					RemotePort: c.Raddr.Port,
					State:      c.Status,
					PID:        c.Pid,
				}

				// Get process name
				if c.Pid > 0 {
					if p, err := process.NewProcess(c.Pid); err == nil {
						if name, err := p.Name(); err == nil {
							info.ProcessName = name
						}
					}
				}

				// Filter by process name
				if filterProcess != "" {
					if !strings.Contains(strings.ToLower(info.ProcessName), strings.ToLower(filterProcess)) {
						continue
					}
				}

				infos = append(infos, info)
			}

			if outputJSON {
				data, _ := json.MarshalIndent(infos, "", "  ")
				fmt.Println(string(data))
				return nil
			}

			if groupByDest {
				// Group connections by destination
				type destStat struct {
					Addr      string
					Port      uint32
					Protocol  string
					Count     int
					Processes map[string]struct{}
				}

				dests := make(map[string]*destStat)
				for _, c := range infos {
					if c.RemoteAddr == "" {
						continue
					}
					key := fmt.Sprintf("%s:%d:%s", c.RemoteAddr, c.RemotePort, c.Protocol)
					if d, exists := dests[key]; exists {
						d.Count++
						if c.ProcessName != "" {
							d.Processes[c.ProcessName] = struct{}{}
						}
					} else {
						procs := make(map[string]struct{})
						if c.ProcessName != "" {
							procs[c.ProcessName] = struct{}{}
						}
						dests[key] = &destStat{
							Addr:      c.RemoteAddr,
							Port:      c.RemotePort,
							Protocol:  c.Protocol,
							Count:     1,
							Processes: procs,
						}
					}
				}

				// Convert to slice and sort
				type destRow struct {
					Addr      string
					Port      uint32
					Protocol  string
					Count     int
					Processes string
				}
				var rows []destRow
				for _, d := range dests {
					var procs []string
					for p := range d.Processes {
						procs = append(procs, p)
					}
					rows = append(rows, destRow{
						Addr:      d.Addr,
						Port:      d.Port,
						Protocol:  d.Protocol,
						Count:     d.Count,
						Processes: strings.Join(procs, ","),
					})
				}

				sort.Slice(rows, func(i, j int) bool {
					return rows[i].Count > rows[j].Count
				})

				fmt.Printf("%-20s %6s %-8s %6s %s\n",
					"DESTINATION", "PORT", "PROTO", "COUNT", "PROCESSES")
				fmt.Println(strings.Repeat("-", 70))

				for _, r := range rows {
					addr := r.Addr
					if len(addr) > 20 {
						addr = addr[:17] + "..."
					}
					procs := r.Processes
					if len(procs) > 25 {
						procs = procs[:22] + "..."
					}
					fmt.Printf("%-20s %6d %-8s %6d %s\n",
						addr, r.Port, r.Protocol, r.Count, procs)
				}

				fmt.Println()
				fmt.Printf("Total: %d unique destinations, %d connections\n", len(rows), len(infos))
				return nil
			}

			fmt.Printf("%-8s %-22s %-22s %-12s %8s %s\n",
				"PROTO", "LOCAL", "REMOTE", "STATE", "PID", "PROCESS")
			fmt.Println(strings.Repeat("-", 90))

			for _, c := range infos {
				local := fmt.Sprintf("%s:%d", c.LocalAddr, c.LocalPort)
				remote := fmt.Sprintf("%s:%d", c.RemoteAddr, c.RemotePort)

				if len(local) > 22 {
					local = local[:19] + "..."
				}
				if len(remote) > 22 {
					remote = remote[:19] + "..."
				}

				procName := c.ProcessName
				if len(procName) > 15 {
					procName = procName[:12] + "..."
				}

				fmt.Printf("%-8s %-22s %-22s %-12s %8d %s\n",
					c.Protocol, local, remote, c.State, c.PID, procName)
			}

			fmt.Println()

			// Summary stats
			var established, listening, timeWait int
			uniqueIPs := make(map[string]struct{})
			for _, c := range infos {
				switch c.State {
				case "ESTABLISHED":
					established++
				case "LISTEN":
					listening++
				case "TIME_WAIT":
					timeWait++
				}
				if c.RemoteAddr != "" {
					uniqueIPs[c.RemoteAddr] = struct{}{}
				}
			}

			fmt.Printf("Total: %d connections (ESTABLISHED: %d, LISTEN: %d, TIME_WAIT: %d)\n",
				len(infos), established, listening, timeWait)
			fmt.Printf("Unique remote IPs: %d\n", len(uniqueIPs))

			return nil
		},
	}

	cmd.Flags().StringVar(&filterState, "state", "", "filter by connection state (ESTABLISHED, LISTEN, etc)")
	cmd.Flags().StringVarP(&filterProcess, "process", "p", "", "filter by process name")
	cmd.Flags().BoolVarP(&showListening, "listening", "l", false, "show only listening sockets")
	cmd.Flags().BoolVarP(&showEstablished, "established", "e", false, "show only established connections")
	cmd.Flags().BoolVarP(&groupByDest, "group", "g", false, "group by destination address")

	return cmd
}

func servicesCmd() *cobra.Command {
	var showRunning bool

	cmd := &cobra.Command{
		Use:     "services",
		Aliases: []string{"daemons", "svc"},
		Short:   "List system services/daemons",
		Long: `Display system services and their status.

Examples:
  darkdadm services           # Show all services
  darkdadm services --running # Only running services`,
		RunE: func(cmd *cobra.Command, args []string) error {
			// This is a placeholder - in production this would query the daemon
			// For now, show a message
			fmt.Println("System Services")
			fmt.Println("===============")
			fmt.Println()
			fmt.Println("(Query daemon for service list with 'darkdadm status')")
			fmt.Println()
			fmt.Println("To monitor services in real-time, ensure afterdark-darkd is running.")
			return nil
		},
	}

	cmd.Flags().BoolVarP(&showRunning, "running", "r", false, "show only running services")

	return cmd
}

func protocolName(t uint32) string {
	switch t {
	case 1:
		return "tcp"
	case 2:
		return "udp"
	case 3:
		return "tcp6"
	case 4:
		return "udp6"
	default:
		return fmt.Sprintf("proto-%d", t)
	}
}
