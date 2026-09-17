package main

import (
	"bytes"
	"encoding/json"
	"github.com/afterdarksys/afterdark-darkd/internal/workflow"
	"github.com/spf13/cobra"
	"os"
	"path/filepath"
	"testing"
)

func TestWorkflowCLI(t *testing.T) {
	source := filepath.Join(t.TempDir(), "source with spaces")
	os.WriteFile(source, []byte("test evidence"), 0600)
	bundle := filepath.Join(t.TempDir(), "bundle")
	cmd := workflowCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetArgs([]string{"run", "evidence-collection", "--case-id", "CASE-1", "--operator", "Analyst", "--artifact", source, "--output", bundle})
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	var m workflow.Manifest
	if err := json.Unmarshal(out.Bytes(), &m); err != nil {
		t.Fatal(err)
	}
	if m.Status != "complete" {
		t.Fatal(m)
	}
	verify := workflowCmd()
	verify.SetOut(&out)
	verify.SetArgs([]string{"verify", bundle})
	if err := verify.Execute(); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	missing := &cobra.Command{Use: "darkdadm"}
	missing.AddCommand(workflowCmd())
	missing.SetOut(&out)
	missing.SetErr(&out)
	missing.SetArgs([]string{"workflow", "run", "evidence-collection", "--case-id", "CASE-1", "--operator", "Analyst", "--artifact", source + "missing", "--output", bundle + "-partial"})
	if _, ok := missing.Execute().(*workflowExit); !ok {
		t.Fatal("partial run did not return collection exit status")
	}
	if err := json.Unmarshal(out.Bytes(), &m); err != nil {
		t.Fatalf("partial result polluted by usage/error output: %s", out.String())
	}
}
