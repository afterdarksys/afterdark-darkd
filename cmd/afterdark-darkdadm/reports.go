package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"time"

	pb "github.com/afterdarksys/afterdark-darkd/api/proto/ipc"
	"github.com/afterdarksys/afterdark-darkd/internal/reporting"
	"github.com/spf13/cobra"
)

func reportsCmd() *cobra.Command {
	var format, output, kind string
	cmd := &cobra.Command{Use: "reports", Short: "Generate reports from authenticated daemon evidence"}
	generate := &cobra.Command{Use: "generate", Args: cobra.NoArgs, Short: "Generate security, compliance, or exposure evidence (JSON/HTML/PDF)", RunE: func(cmd *cobra.Command, args []string) error {
		if format != "json" && format != "html" && format != "pdf" {
			return fmt.Errorf("format must be json, html, or pdf")
		}
		if kind != "security" && kind != "compliance" && kind != "exposure" {
			return fmt.Errorf("kind must be security, compliance, or exposure")
		}
		ctx, cancel := context.WithTimeout(cmd.Context(), 30*time.Second)
		defer cancel()
		client, err := newAdminClient(ctx)
		if err != nil {
			return err
		}
		report := reporting.Report{GeneratedAt: time.Now().UTC(), Kind: kind, Complete: true}
		status, err := client.GetStatus(ctx, &pb.StatusRequest{})
		if err != nil {
			return fmt.Errorf("daemon status: %w", err)
		}
		report.Add("Daemon status", status, nil)
		health, err := client.GetHealth(ctx, &pb.HealthRequest{})
		report.Add("Service health", health, err)
		if kind != "exposure" {
			compliance, err := client.GetCompliance(ctx, &pb.GetComplianceRequest{})
			report.Add("Patch compliance", compliance, err)
			patches, err := client.ListPatches(ctx, &pb.ListPatchesRequest{})
			report.Add("Patches", patches, err)
			for _, action := range []string{"check_cis", "check_compliance"} {
				evidence, fetchErr := client.ManagePlugin(ctx, &pb.PluginRequest{Action: "execute", Name: "contextacld", PluginAction: action, ParamsJson: "{}"})
				var result any
				if fetchErr == nil {
					fetchErr = json.Unmarshal([]byte(evidence.ResultJson), &result)
				}
				report.Add("Device policy: "+action, result, fetchErr)
			}
		}
		if kind != "compliance" {
			threats, err := client.GetThreatStatus(ctx, &pb.GetThreatStatusRequest{})
			report.Add("Threat intelligence", threats, err)
			connections, err := client.GetConnections(ctx, &pb.GetConnectionsRequest{Limit: 1000})
			report.Add("Network connections (limit 1000)", connections, err)
			events, err := client.GetEvents(ctx, &pb.GetEventsRequest{Limit: 1000})
			report.Add("Recent events (limit 1000)", events, err)
		}
		if output == "" || output == "-" {
			err = reporting.Write(cmd.OutOrStdout(), format, report)
		} else {
			// Never truncate an existing report or follow an existing symlink.
			var f *os.File
			f, err = os.OpenFile(output, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
			if err == nil {
				err = reporting.Write(f, format, report)
				closeErr := f.Close()
				if err == nil {
					err = closeErr
				}
			}
		}
		if err != nil {
			return err
		}
		if !report.Complete {
			return fmt.Errorf("report is incomplete; see unavailable sections in the output")
		}
		return nil
	}}
	generate.Flags().StringVar(&format, "format", "json", "json, html, or pdf")
	generate.Flags().StringVar(&output, "output", "-", "new output file, or - for stdout")
	generate.Flags().StringVar(&kind, "kind", "security", "security, compliance, or exposure")
	cmd.AddCommand(generate)
	return cmd
}
