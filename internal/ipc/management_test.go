package ipc

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	pb "github.com/afterdarksys/afterdark-darkd/api/proto/ipc"
	"github.com/afterdarksys/afterdark-darkd/internal/plugin"
	"go.uber.org/zap"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestManagementRejectsUntrustedPaths(t *testing.T) {
	dir := t.TempDir()
	s := &Server{config: &Config{PluginHost: plugin.NewHost(dir, zap.NewNop())}}
	for _, name := range []string{"../evil", "/tmp/evil", `..\evil`, ""} {
		_, err := s.ManagePlugin(context.Background(), &pb.PluginRequest{Action: "enable", Name: name})
		if status.Code(err) != codes.InvalidArgument {
			t.Fatalf("%q: %v", name, err)
		}
	}
	// Executable presence alone cannot bypass Host signature validation.
	if err := os.WriteFile(filepath.Join(dir, "unsigned"), []byte("#!/bin/sh\nexit 0\n"), 0700); err != nil {
		t.Fatal(err)
	}
	_, err := s.ManagePlugin(context.Background(), &pb.PluginRequest{Action: "enable", Name: "unsigned"})
	if err == nil {
		t.Fatal("unsigned plugin enabled")
	}
	listed, err := s.ManagePlugin(context.Background(), &pb.PluginRequest{Action: "list"})
	if err != nil {
		t.Fatal(err)
	}
	var rows []map[string]any
	if err := json.Unmarshal([]byte(listed.ResultJson), &rows); err != nil {
		t.Fatal(err)
	}
	for _, row := range rows {
		if row["enabled"] != false {
			t.Fatal("failed plugin reported enabled")
		}
	}
}

func TestProfilesValidateRequestsAndCollectMemory(t *testing.T) {
	s := &Server{}
	for _, req := range []*pb.ProfileRequest{{Kind: "invalid"}, {Kind: "cpu", Seconds: 0}, {Kind: "cpu", Seconds: 61}} {
		if _, err := s.CaptureProfile(context.Background(), req); status.Code(err) != codes.InvalidArgument {
			t.Fatalf("invalid request: %v", err)
		}
	}
	result, err := s.CaptureProfile(context.Background(), &pb.ProfileRequest{Kind: "mem"})
	if err != nil {
		t.Fatal(err)
	}
	var metrics map[string]any
	if err := json.Unmarshal(result.Data, &metrics); err != nil {
		t.Fatal(err)
	}
	if metrics["Alloc"].(float64) <= 0 {
		t.Fatal("missing memory measurement")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := s.CaptureProfile(ctx, &pb.ProfileRequest{Kind: "cpu", Seconds: 1}); status.Code(err) != codes.Canceled {
		t.Fatal(err)
	}
}
