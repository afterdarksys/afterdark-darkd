//go:build !windows

// Integration tests for the IPC server. They start a real gRPC server on a
// temporary Unix socket, dial it with the client helpers, and verify end-to-end
// behaviour including auth token enforcement.

package ipc

import (
	"context"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"os"
	"path/filepath"
	"testing"
	"time"

	pb "github.com/afterdarksys/afterdark-darkd/api/proto/ipc"
	"github.com/afterdarksys/afterdark-darkd/internal/ipc/peercred"
)

// startTestServer starts an IPC server on a temp socket and returns a cleanup func.
func startTestServer(t *testing.T, requireAuth bool) (socketPath, token string, cleanup func()) {
	t.Helper()

	// macOS limits Unix-domain socket paths to a short fixed-size buffer. The
	// default t.TempDir path under /var/folders can exceed that limit, causing
	// listen(2) to fail with EINVAL before the test exercises IPC at all.
	dir, err := os.MkdirTemp("/tmp", "darkd-ipc-")
	if err != nil {
		t.Fatalf("creating short temp dir: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	socketPath = filepath.Join(dir, "darkd-test.sock")
	tokenPath := filepath.Join(dir, ".auth_token")

	cfg := &Config{
		SocketPath:             socketPath,
		AuthTokenPath:          tokenPath,
		RequireAuth:            requireAuth,
		RequirePeerCredentials: true,
		AllowedPeerUIDs:        []uint32{peercred.CurrentUID()},
	}

	srv, err := New(cfg, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ctx := context.Background()
	if err := srv.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}

	if requireAuth {
		raw, err := os.ReadFile(tokenPath)
		if err != nil {
			t.Fatalf("reading token: %v", err)
		}
		token = string(raw)
	}

	cleanup = func() {
		stopCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Stop(stopCtx)
	}
	return socketPath, token, cleanup
}

func TestIntegration_GetStatus(t *testing.T) {
	sockPath, token, cleanup := startTestServer(t, true)
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	client, err := NewClientWithToken(ctx, sockPath, token)
	if err != nil {
		t.Fatalf("NewClientWithToken: %v", err)
	}

	resp, err := client.GetStatus(ctx, &pb.StatusRequest{})
	if err != nil {
		t.Fatalf("GetStatus: %v", err)
	}
	if resp.Version == "" {
		t.Error("expected non-empty version")
	}
	if resp.Pid == 0 {
		t.Error("expected non-zero PID")
	}
}

func TestIntegration_GetHealth(t *testing.T) {
	sockPath, token, cleanup := startTestServer(t, true)
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	client, err := NewClientWithToken(ctx, sockPath, token)
	if err != nil {
		t.Fatalf("NewClientWithToken: %v", err)
	}

	resp, err := client.GetHealth(ctx, &pb.HealthRequest{})
	if err != nil {
		t.Fatalf("GetHealth: %v", err)
	}
	if resp.Status == "" {
		t.Error("expected non-empty health status")
	}
}

func TestIntegration_AuthRejectedWithoutToken(t *testing.T) {
	sockPath, _, cleanup := startTestServer(t, true)
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Connect without a token — server requires auth, so the RPC must fail.
	client, err := NewClient(ctx, sockPath)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	_, err = client.GetStatus(ctx, &pb.StatusRequest{})
	if err == nil {
		t.Error("expected auth error when no token provided, got nil")
	}
}

func TestIntegration_AuthRejectedWithWrongToken(t *testing.T) {
	sockPath, _, cleanup := startTestServer(t, true)
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	client, err := NewClientWithToken(ctx, sockPath, "totallyWrongToken")
	if err != nil {
		t.Fatalf("NewClientWithToken: %v", err)
	}

	_, err = client.GetStatus(ctx, &pb.StatusRequest{})
	if err == nil {
		t.Error("expected auth error with wrong token, got nil")
	}
}

func TestIntegration_NoAuthMode(t *testing.T) {
	sockPath, _, cleanup := startTestServer(t, false)
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// No token needed when auth is disabled.
	client, err := NewClient(ctx, sockPath)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	resp, err := client.GetStatus(ctx, &pb.StatusRequest{})
	if err != nil {
		t.Fatalf("GetStatus without auth: %v", err)
	}
	if resp.Pid == 0 {
		t.Error("expected non-zero PID")
	}
}

// TCP TLS and Unix peer authentication must coexist after merging the transports.
func TestIntegration_TCPWithTokenAndTLS(t *testing.T) {
	dir := t.TempDir()
	tokenPath := filepath.Join(dir, ".auth_token")
	t.Setenv("AFTERDARK_AUTH_TOKEN_FILE", tokenPath)
	cfg := DefaultConfig()
	cfg.TCPAddr = "127.0.0.1:0"
	cfg.AuthTokenPath = tokenPath
	cfg.CertDir = filepath.Join(dir, "ipc-tls")
	srv, err := New(cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := srv.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer srv.Stop(context.Background())
	conn, err := DialWithCertDir(ctx, srv.Address(), cfg.CertDir)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := pb.NewDaemonServiceClient(conn).GetStatus(ctx, &pb.StatusRequest{}); err != nil {
		t.Fatal(err)
	}
	unauthenticated, err := dialWithOptions(ctx, srv.Address(), cfg.CertDir, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer unauthenticated.Close()
	if _, err := pb.NewDaemonServiceClient(unauthenticated).GetStatus(ctx, &pb.StatusRequest{}); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("missing token: %v", err)
	}
}

func TestIntegration_ProfilesRequireAuthentication(t *testing.T) {
	socket, token, cleanup := startTestServer(t, true)
	defer cleanup()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	wrong, err := NewClientWithToken(ctx, socket, "incorrect")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := wrong.CaptureProfile(ctx, &pb.ProfileRequest{Kind: "mem"}); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("unauthenticated profile: %v", err)
	}
	if _, err := wrong.ManagePlugin(ctx, &pb.PluginRequest{Action: "list"}); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("unauthenticated plugins: %v", err)
	}
	client, err := NewClientWithToken(ctx, socket, token)
	if err != nil {
		t.Fatal(err)
	}
	result, err := client.CaptureProfile(ctx, &pb.ProfileRequest{Kind: "heap"})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Data) < 2 || result.Data[0] != 0x1f || result.Data[1] != 0x8b {
		t.Fatal("heap response is not a gzip pprof profile")
	}
}
