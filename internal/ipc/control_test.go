//go:build !windows

package ipc

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	pb "github.com/afterdarksys/afterdark-darkd/api/proto/ipc"
	"github.com/afterdarksys/afterdark-darkd/internal/control"
	"github.com/afterdarksys/afterdark-darkd/internal/events"
	"github.com/afterdarksys/afterdark-darkd/internal/ipc/peercred"
	"github.com/afterdarksys/afterdark-darkd/internal/service"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

const controlTestSystem = "sys-ipc-test"

type controlHarness struct {
	socket, token string
	priv          ed25519.PrivateKey
	window        *control.Window
	store         *events.Store
	stopped       chan struct{}
}

// startControlServer runs a real IPC server with a Controller whose key file
// is owned by the test uid (root ownership cannot be produced unprivileged).
func startControlServer(t *testing.T, withController bool) *controlHarness {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "darkd-ctl-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	privPath, _, pub, err := control.GenerateKeyPair(filepath.Join(dir, "operator"))
	if err != nil {
		t.Fatal(err)
	}
	priv, err := control.LoadPrivateKey(privPath)
	if err != nil {
		t.Fatal(err)
	}
	keysDir := filepath.Join(dir, "etc")
	if err := os.Mkdir(keysDir, 0755); err != nil {
		t.Fatal(err)
	}
	keysFile := filepath.Join(keysDir, "control-stop-keys.pub")
	if err := os.WriteFile(keysFile, []byte(base64.StdEncoding.EncodeToString(pub)+"\n"), 0644); err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()
	store := events.New(filepath.Join(dir, "events.db"), "endpoint-a")
	if err := store.Start(ctx); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Stop(context.Background()) })
	registry := service.NewRegistry()
	if err := registry.Register(store); err != nil {
		t.Fatal(err)
	}

	h := &controlHarness{priv: priv, window: control.NewWindow(), store: store, stopped: make(chan struct{}, 1)}
	cfg := &Config{
		SocketPath:             filepath.Join(dir, "d.sock"),
		AuthTokenPath:          filepath.Join(dir, ".auth_token"),
		RequireAuth:            true,
		RequirePeerCredentials: true,
		AllowedPeerUIDs:        []uint32{peercred.CurrentUID()},
		OnControlStop:          func() { h.stopped <- struct{}{} },
	}
	if withController {
		cfg.Control, err = control.New(control.Config{
			KeysFile:  keysFile,
			KeysOwner: peercred.CurrentUID(),
			NonceFile: filepath.Join(dir, "data", control.NonceFileName),
			SystemID:  func() (string, error) { return controlTestSystem, nil },
			Window:    h.window,
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	srv, err := New(cfg, registry)
	if err != nil {
		t.Fatal(err)
	}
	if err := srv.Start(ctx); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		stopCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		srv.Stop(stopCtx)
	})
	raw, err := os.ReadFile(cfg.AuthTokenPath)
	if err != nil {
		t.Fatal(err)
	}
	h.socket, h.token = cfg.SocketPath, string(raw)
	return h
}

func (h *controlHarness) signed(t *testing.T, action string) []byte {
	t.Helper()
	claims, err := control.NewClaims(action, controlTestSystem, time.Now(), 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	tok, err := control.SignToken(h.priv, claims)
	if err != nil {
		t.Fatal(err)
	}
	return []byte(tok)
}

func (h *controlHarness) client(t *testing.T, ctx context.Context, token string) pb.ControlServiceClient {
	t.Helper()
	client, err := NewControlClientWithToken(ctx, h.socket, token)
	if err != nil {
		t.Fatal(err)
	}
	return client
}

func (h *controlHarness) controlEvents(t *testing.T) []events.Event {
	t.Helper()
	list, err := h.store.ListRecent(context.Background(), 50, time.Time{}, "agent.control", "")
	if err != nil {
		t.Fatal(err)
	}
	return list
}

func setControlPeerUID(t *testing.T, uid uint32) {
	t.Helper()
	previous := controlPeerUID
	controlPeerUID = uid
	t.Cleanup(func() { controlPeerUID = previous })
}

func TestControlStopRejectsNonRootPeer(t *testing.T) {
	h := startControlServer(t, true)
	// The test peer's uid is never the required uid here, whether or not the
	// suite runs as root.
	setControlPeerUID(t, peercred.CurrentUID()+1)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	tok := h.signed(t, control.ActionUpgrade)
	_, err := h.client(t, ctx, h.token).Stop(ctx, &pb.ControlStopRequest{Token: tok})
	if status.Code(err) != codes.PermissionDenied || !strings.Contains(err.Error(), "uid 0") {
		t.Fatalf("non-root peer: %v", err)
	}
	if h.window.Open() {
		t.Fatal("window opened for a non-root peer")
	}
	denied := h.controlEvents(t)
	if len(denied) != 1 || denied[0].Facts["control.outcome"] != "denied" {
		t.Fatalf("denial not journaled: %+v", denied)
	}
	// The rejection happened before the token was examined: it is unspent.
	setControlPeerUID(t, peercred.CurrentUID())
	if _, err := h.client(t, ctx, h.token).Stop(ctx, &pb.ControlStopRequest{Token: tok}); err != nil {
		t.Fatalf("token was consumed by a rejected peer: %v", err)
	}
}

func TestControlStopRequiresBearerToken(t *testing.T) {
	h := startControlServer(t, true)
	setControlPeerUID(t, peercred.CurrentUID())
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err := h.client(t, ctx, "wrong").Stop(ctx, &pb.ControlStopRequest{Token: h.signed(t, control.ActionStop)})
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("wrong bearer token: %v", err)
	}
	if h.window.Open() {
		t.Fatal("window opened without IPC authentication")
	}
}

func TestControlStopAcceptsSignedTokenOnce(t *testing.T) {
	h := startControlServer(t, true)
	setControlPeerUID(t, peercred.CurrentUID())
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	client := h.client(t, ctx, h.token)
	tok := h.signed(t, control.ActionStop)
	resp, err := client.Stop(ctx, &pb.ControlStopRequest{Token: tok})
	if err != nil {
		t.Fatal(err)
	}
	if resp.Action != control.ActionStop || resp.WindowSeconds != 120 || !strings.HasPrefix(resp.KeyFingerprint, "SHA256:") {
		t.Fatalf("response: %+v", resp)
	}
	if !h.window.Open() {
		t.Fatal("window not open after an accepted token")
	}
	select {
	case <-h.stopped:
	case <-time.After(2 * time.Second):
		t.Fatal("stop action did not start a shutdown")
	}
	accepted := h.controlEvents(t)
	if len(accepted) != 1 || accepted[0].Facts["control.outcome"] != "accepted" || accepted[0].Facts["control.action"] != "stop" {
		t.Fatalf("acceptance not journaled: %+v", accepted)
	}
	for _, e := range accepted {
		if strings.Contains(string(e.Data), string(tok)) || strings.Contains(string(e.Data), strings.Split(string(tok), ".")[1]) {
			t.Fatal("journal holds the raw token")
		}
	}
	if _, err := client.Stop(ctx, &pb.ControlStopRequest{Token: tok}); status.Code(err) != codes.PermissionDenied || !strings.Contains(err.Error(), "already used") {
		t.Fatalf("replay over IPC: %v", err)
	}
	if _, err := client.Stop(ctx, &pb.ControlStopRequest{Token: []byte(strings.Repeat("A", control.MaxTokenSize+1))}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("oversized token over IPC: %v", err)
	}
}

func TestControlUpgradeLeavesDaemonRunning(t *testing.T) {
	h := startControlServer(t, true)
	setControlPeerUID(t, peercred.CurrentUID())
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	resp, err := h.client(t, ctx, h.token).Stop(ctx, &pb.ControlStopRequest{Token: h.signed(t, control.ActionUpgrade)})
	if err != nil || resp.Action != control.ActionUpgrade {
		t.Fatalf("upgrade: %+v %v", resp, err)
	}
	if !h.window.Open() {
		t.Fatal("upgrade did not open the window")
	}
	select {
	case <-h.stopped:
		t.Fatal("upgrade initiated a shutdown")
	case <-time.After(200 * time.Millisecond):
	}
}

func TestControlStopWithoutControllerFailsClosed(t *testing.T) {
	h := startControlServer(t, false)
	setControlPeerUID(t, peercred.CurrentUID())
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err := h.client(t, ctx, h.token).Stop(ctx, &pb.ControlStopRequest{Token: h.signed(t, control.ActionStop)})
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "no control stop public key") {
		t.Fatalf("no controller: %v", err)
	}
}

type otherAuthInfo struct{ credentials.CommonAuthInfo }

func (otherAuthInfo) AuthType() string { return "tls" }

func TestControlPeerRequiresUnixPeerCredentials(t *testing.T) {
	setControlPeerUID(t, 0)
	if _, err := controlPeer(context.Background()); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("no peer: %v", err)
	}
	tcp := peer.NewContext(context.Background(), &peer.Peer{AuthInfo: otherAuthInfo{}})
	if _, err := controlPeer(tcp); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("TCP/TLS peer: %v", err)
	}
	user := peer.NewContext(context.Background(), &peer.Peer{AuthInfo: &localAuthInfo{UID: 501}})
	if _, err := controlPeer(user); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("uid 501 peer: %v", err)
	}
	root := peer.NewContext(context.Background(), &peer.Peer{AuthInfo: &localAuthInfo{UID: 0}})
	if uid, err := controlPeer(root); err != nil || uid != 0 {
		t.Fatalf("root peer: %d %v", uid, err)
	}
}
