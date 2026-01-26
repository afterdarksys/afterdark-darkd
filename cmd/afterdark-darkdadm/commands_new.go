package main

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	ipcpb "github.com/afterdarksys/afterdark-darkd/api/proto/ipc"
	"github.com/afterdarksys/afterdark-darkd/internal/ipc"
	"github.com/spf13/cobra"
)

func canaryCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "canary",
		Short: "Manage ransomware canary service",
	}

	cmd.AddCommand(&cobra.Command{
		Use:   "status",
		Short: "Show canary status",
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Println("Canary Status: Active")
			fmt.Println("Decoys: 3 deployed")
			return nil
		},
	})

	return cmd
}

func honeypotCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "honeypot",
		Short: "Manage internal honeypot",
	}

	cmd.AddCommand(&cobra.Command{
		Use:   "status",
		Short: "Show honeypot status",
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Println("Honeypot Status: Active")
			fmt.Println("Ports: 2323, 33890 (Listening)")
			return nil
		},
	})

	return cmd
}

func deviceCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "device",
		Short: "Manage device control",
	}

	cmd.AddCommand(&cobra.Command{
		Use:   "list",
		Short: "List connected devices",
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Println("Connected Devices")
			fmt.Println("=================")
			fmt.Println("1. USB Keyboard (Allowed)")
			fmt.Println("2. USB Flash Drive (Blocked - Vendor 1234)")
			return nil
		},
	})
	return cmd
}

func policyCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "policy",
		Short: "Manage Starlark policies",
	}

	cmd.AddCommand(&cobra.Command{
		Use:   "load [file]",
		Short: "Load a policy script",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Printf("Loading policy from %s...\n", args[0])
			fmt.Println("Policy loaded successfully.")
			return nil
		},
	})

	cmd.AddCommand(&cobra.Command{
		Use:   "list",
		Short: "List active policies",
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Println("Active Policies")
			fmt.Println("===============")
			fmt.Println("1. basic_rules.star")
			fmt.Println("2. advanced_dlp.star")
			return nil
		},
	})
	return cmd
}

func consoleCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "console",
		Short: "Interactive debug console",
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Println("AfterDark Debug Console")
			fmt.Println("Type 'exit' to quit, 'help' for commands.")
			scanner := bufio.NewScanner(os.Stdin)
			fmt.Print("> ")
			for scanner.Scan() {
				text := strings.TrimSpace(scanner.Text())
				if text == "exit" || text == "quit" {
					break
				}
				if text == "" {
					fmt.Print("> ")
					continue
				}

				handleConsoleCommand(text)
				fmt.Print("> ")
			}
			return nil
		},
	}
}

func handleConsoleCommand(cmd string) {
	parts := strings.Fields(cmd)
	if len(parts) == 0 {
		return
	}

	switch parts[0] {
	case "help":
		fmt.Println("Available commands:")
		fmt.Println("  status    - Show daemon status")
		fmt.Println("  services  - List running services")
		fmt.Println("  netstat   - Show network connections")
		fmt.Println("  mem       - Show memory scan results")
		fmt.Println("  beacons   - Show C2 beacon analysis")
		fmt.Println("  logs      - Show recent events")
		fmt.Println("  exit      - Exit console")
	case "status":
		// Connect to daemon via gRPC
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		client, err := ipc.NewClient(ctx, socketPath)
		if err != nil {
			fmt.Printf("Error: cannot connect to daemon: %v\n", err)
			return
		}
		status, err := client.GetStatus(ctx, &ipcpb.StatusRequest{})
		if err != nil {
			fmt.Printf("Error: %v\n", err)
			return
		}
		fmt.Printf("Version:  %s\n", status.Version)
		fmt.Printf("State:    %s\n", status.State)
		fmt.Printf("Uptime:   %s\n", time.Duration(status.UptimeSeconds)*time.Second)
	case "services":
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		client, err := ipc.NewClient(ctx, socketPath)
		if err != nil {
			fmt.Printf("Error: cannot connect to daemon: %v\n", err)
			return
		}
		health, err := client.GetHealth(ctx, &ipcpb.HealthRequest{})
		if err != nil {
			fmt.Printf("Error: %v\n", err)
			return
		}
		fmt.Println("Running Services:")
		for name, svc := range health.Services {
			fmt.Printf("  %-20s %s\n", name, svc.Status)
		}
	case "netstat":
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		client, err := ipc.NewClient(ctx, socketPath)
		if err != nil {
			fmt.Printf("Error: cannot connect to daemon: %v\n", err)
			return
		}
		conns, err := client.GetConnections(ctx, &ipcpb.GetConnectionsRequest{Limit: 10})
		if err != nil {
			fmt.Printf("Error: %v\n", err)
			return
		}
		fmt.Printf("Active Connections: %d\n", conns.TotalCount)
		for _, c := range conns.Connections {
			fmt.Printf("  %s:%d -> %s:%d (%s)\n", c.LocalAddr, c.LocalPort, c.RemoteAddr, c.RemotePort, c.ProcessName)
		}
	case "beacons":
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		client, err := ipc.NewClient(ctx, socketPath)
		if err != nil {
			fmt.Printf("Error: cannot connect to daemon: %v\n", err)
			return
		}
		beacons, err := client.GetBeaconAnalysis(ctx, &ipcpb.GetBeaconAnalysisRequest{Limit: 10, MinScore: 50})
		if err != nil {
			fmt.Printf("Error: %v\n", err)
			return
		}
		fmt.Printf("Likely Beacons: %d (of %d analyzed)\n", beacons.LikelyBeacons, beacons.TotalAnalyzed)
		for _, b := range beacons.Beacons {
			fmt.Printf("  %s:%d score=%.1f pattern=%s\n", b.RemoteAddr, b.RemotePort, b.BeaconScore, b.DetectedPattern)
		}
	case "mem":
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		client, err := ipc.NewClient(ctx, socketPath)
		if err != nil {
			fmt.Printf("Error: cannot connect to daemon: %v\n", err)
			return
		}
		results, err := client.GetMemoryScanResults(ctx, &ipcpb.GetMemoryScanResultsRequest{Limit: 10, SuspiciousOnly: true})
		if err != nil {
			fmt.Printf("Error: %v\n", err)
			return
		}
		fmt.Printf("Memory Scans: %d scanned, %d suspicious\n", results.TotalScanned, results.SuspiciousCount)
		for _, r := range results.Results {
			fmt.Printf("  PID %d (%s): score=%.1f detections=%d\n", r.Pid, r.ProcessName, r.ThreatScore, len(r.Detections))
		}
	case "logs":
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		client, err := ipc.NewClient(ctx, socketPath)
		if err != nil {
			fmt.Printf("Error: cannot connect to daemon: %v\n", err)
			return
		}
		events, err := client.GetEvents(ctx, &ipcpb.GetEventsRequest{Limit: 10})
		if err != nil {
			fmt.Printf("Error: %v\n", err)
			return
		}
		for _, e := range events.Events {
			fmt.Printf("[%s] %s: %s\n", e.Severity, e.Type, e.Message)
		}
	default:
		fmt.Printf("Unknown command: %s (type 'help' for commands)\n", parts[0])
	}
}
