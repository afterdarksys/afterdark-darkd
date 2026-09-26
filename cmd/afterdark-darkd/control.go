package main

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	pb "github.com/afterdarksys/afterdark-darkd/api/proto/ipc"
	"github.com/afterdarksys/afterdark-darkd/internal/control"
	"github.com/afterdarksys/afterdark-darkd/internal/daemon"
	"github.com/afterdarksys/afterdark-darkd/internal/ipc"
)

// controlToken is a signed stop/upgrade token file, or - for stdin.
var controlToken string

// presentControlToken opens darkd's maintenance window before launchctl
// unloads it. Without a token, Endpoint Security self-protection would deny
// the unload, so this fails first with instructions.
func presentControlToken() error {
	if controlToken == "" {
		return fmt.Errorf("darkd self-protection denies launchctl unload without a signed token: pass --control-token <file|-> " +
			"(sign one offline with 'afterdark-darkdadm control sign-stop --action upgrade --system-id <id> --key <private key>')")
	}
	token, err := control.ReadToken(controlToken, os.Stdin)
	if err != nil {
		return err
	}
	socket, authFile := ipc.DefaultSocketPath, ipc.DefaultAuthTokenPath()
	if cfg, err := daemon.LoadConfigWithMode(configPath, deploymentMode); err == nil {
		if cfg.IPC.SocketPath != "" {
			socket = cfg.IPC.SocketPath
		}
		if cfg.IPC.AuthTokenFile != "" {
			authFile = cfg.IPC.AuthTokenFile
		}
	} else {
		fmt.Fprintf(os.Stderr, "warning: %v; using default IPC socket %s\n", err, socket)
	}
	auth, err := os.ReadFile(authFile)
	if err != nil {
		return fmt.Errorf("read IPC auth token: %w", err)
	}
	if strings.TrimSpace(string(auth)) == "" {
		return fmt.Errorf("IPC auth token %s is empty", authFile)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	client, err := ipc.NewControlClientWithToken(ctx, socket, strings.TrimSpace(string(auth)))
	if err != nil {
		return fmt.Errorf("connect to darkd: %w", err)
	}
	resp, err := client.Stop(ctx, &pb.ControlStopRequest{Token: token})
	if err != nil {
		return fmt.Errorf("darkd rejected the control token: %w", err)
	}
	fmt.Printf("darkd accepted %s token (key %s); maintenance window %ds\n", resp.Action, resp.KeyFingerprint, resp.WindowSeconds)
	return nil
}
