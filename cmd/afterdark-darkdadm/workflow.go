package main

import (
	"encoding/json"
	"fmt"
	"github.com/afterdarksys/afterdark-darkd/internal/workflow"
	"github.com/spf13/cobra"
	"os"
	"os/signal"
)

type workflowExit struct{}

func (*workflowExit) Error() string { return "workflow collection incomplete" }

func workflowCmd() *cobra.Command {
	root := &cobra.Command{Use: "workflow", Short: "Select, plan, run and verify shared security workflows", SilenceUsage: true, SilenceErrors: true}
	emit := func(cmd *cobra.Command, v any) error { return json.NewEncoder(cmd.OutOrStdout()).Encode(v) }
	root.AddCommand(&cobra.Command{Use: "list", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, args []string) error { return emit(cmd, workflow.Catalog()) }})
	for _, action := range []string{"plan", "run"} {
		var req workflow.Request
		var output string
		c := &cobra.Command{Use: action + " WORKFLOW", Args: cobra.ExactArgs(1), SilenceErrors: true, SilenceUsage: true, RunE: func(cmd *cobra.Command, args []string) error {
			req.Workflow = args[0]
			if action == "plan" {
				d, err := workflow.Plan(req)
				if err != nil {
					return err
				}
				return emit(cmd, d)
			}
			if output == "" {
				return fmt.Errorf("--output must name a new evidence bundle directory")
			}
			ctx, cancel := signal.NotifyContext(cmd.Context(), os.Interrupt)
			defer cancel()
			m, err := workflow.Run(ctx, req, output, nil)
			if err != nil {
				return err
			}
			if err = emit(cmd, m); err != nil {
				return err
			}
			if m.Status != "complete" {
				return &workflowExit{}
			}
			return nil
		}}
		c.Flags().StringVar(&req.CaseID, "case-id", "", "Case identifier (required for evidence collection)")
		c.Flags().StringVar(&req.Operator, "operator", "", "Operator label (asserted, not authenticated identity)")
		c.Flags().StringArrayVar(&req.Artifacts, "artifact", nil, "Absolute regular-file path to acquire; repeat for each file")
		if action == "run" {
			c.Flags().StringVar(&output, "output", "", "New bundle directory; parent must exist")
		}
		root.AddCommand(c)
	}
	root.AddCommand(&cobra.Command{Use: "show BUNDLE", Args: cobra.ExactArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
		m, err := workflow.Read(args[0])
		if err != nil {
			return err
		}
		return emit(cmd, m)
	}})
	root.AddCommand(&cobra.Command{Use: "verify BUNDLE", Args: cobra.ExactArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
		m, err := workflow.Verify(args[0])
		if err != nil {
			return err
		}
		return emit(cmd, map[string]any{"verified": true, "run_id": m.ID, "scope": "bytes against unsigned manifest"})
	}})
	return root
}
