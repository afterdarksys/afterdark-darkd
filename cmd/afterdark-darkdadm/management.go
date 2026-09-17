package main

import (
	"context"
	"fmt"
	"os"
	"time"

	pb "github.com/afterdarksys/afterdark-darkd/api/proto/ipc"
	"github.com/spf13/cobra"
)

func pluginCmd() *cobra.Command {
	root := &cobra.Command{Use: "plugin", Short: "Manage trusted plugins in the current daemon session"}
	catalogCommands(root)
	for _, action := range []string{"list", "enable", "disable", "reload", "execute"} {
		action := action
		command := &cobra.Command{Use: action, Args: cobra.ExactArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
			req := &pb.PluginRequest{Action: action}
			if len(args) > 0 {
				req.Name = args[0]
			}
			if action == "execute" {
				req.PluginAction = args[1]
				if len(args) > 2 {
					req.ParamsJson = args[2]
				}
			}
			ctx, cancel := context.WithTimeout(cmd.Context(), 30*time.Second)
			defer cancel()
			client, err := newAdminClient(ctx)
			if err != nil {
				return err
			}
			result, err := client.ManagePlugin(ctx, req)
			if err != nil {
				return err
			}
			_, err = fmt.Fprintln(cmd.OutOrStdout(), result.ResultJson)
			return err
		}}
		if action == "list" {
			command.Args = cobra.NoArgs
		} else if action == "execute" {
			command.Use += " <name> <action> [json-parameters]"
			command.Args = cobra.RangeArgs(2, 3)
		} else {
			command.Use += " <name>"
		}
		root.AddCommand(command)
	}
	return root
}

func profileCmd() *cobra.Command {
	root := &cobra.Command{Use: "profile", Short: "Capture daemon CPU, heap, or memory metrics"}
	for _, kind := range []string{"cpu", "heap", "mem"} {
		kind := kind
		var output string
		var seconds int
		command := &cobra.Command{Use: kind, Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, args []string) error {
			if seconds < 1 || seconds > 60 {
				return fmt.Errorf("seconds must be between 1 and 60")
			}
			ctx, cancel := context.WithTimeout(cmd.Context(), time.Duration(seconds+15)*time.Second)
			defer cancel()
			client, err := newAdminClient(ctx)
			if err != nil {
				return err
			}
			result, err := client.CaptureProfile(ctx, &pb.ProfileRequest{Kind: kind, Seconds: int32(seconds)})
			if err != nil {
				return err
			}
			if output == "-" {
				_, err = cmd.OutOrStdout().Write(result.Data)
				return err
			}
			f, err := os.OpenFile(output, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
			if err != nil {
				return err
			}
			_, err = f.Write(result.Data)
			closeErr := f.Close()
			if err != nil {
				return err
			}
			return closeErr
		}}
		defaultOutput := kind + ".pprof"
		if kind == "mem" {
			defaultOutput = "-"
		}
		command.Flags().StringVar(&output, "output", defaultOutput, "new output file, or - for stdout")
		if kind == "cpu" {
			command.Flags().IntVar(&seconds, "seconds", 30, "CPU sample duration (1-60 seconds)")
		} else {
			seconds = 1
		}
		root.AddCommand(command)
	}
	return root
}
