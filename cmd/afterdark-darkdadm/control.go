package main

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	pb "github.com/afterdarksys/afterdark-darkd/api/proto/ipc"
	"github.com/afterdarksys/afterdark-darkd/internal/control"
	"github.com/afterdarksys/afterdark-darkd/internal/ipc"
	"github.com/spf13/cobra"
)

// stopCmd presents a signed stop/upgrade token to the running daemon.
func stopCmd() *cobra.Command {
	var tokenPath string
	cmd := &cobra.Command{
		Use:   "stop --token <file|->",
		Short: "Present a signed stop or upgrade token to the daemon",
		Long: `Present a token produced offline by 'darkdadm control sign-stop'.

A "stop" token makes darkd shut itself down. An "upgrade" token keeps it
running and opens a 120 second maintenance window in which launchctl may
unload, replace, and reload it. Must be run as root.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			token, err := control.ReadToken(tokenPath, cmd.InOrStdin())
			if err != nil {
				return err
			}
			ctx, cancel := context.WithTimeout(cmd.Context(), 30*time.Second)
			defer cancel()
			client, err := newControlClient(ctx)
			if err != nil {
				return err
			}
			resp, err := client.Stop(ctx, &pb.ControlStopRequest{Token: token})
			if err != nil {
				return fmt.Errorf("daemon rejected the control token: %w", err)
			}
			_, err = fmt.Fprintf(cmd.OutOrStdout(), "accepted %s (key %s); maintenance window %ds: %s\n", resp.Action, resp.KeyFingerprint, resp.WindowSeconds, resp.Message)
			return err
		},
	}
	cmd.Flags().StringVar(&tokenPath, "token", "", "token file, or - for stdin (required)")
	return cmd
}

func newControlClient(ctx context.Context) (pb.ControlServiceClient, error) {
	tokenBytes, err := os.ReadFile(tokenFile)
	if err != nil {
		return nil, fmt.Errorf("read IPC auth token: %w", err)
	}
	token := strings.TrimSpace(string(tokenBytes))
	if token == "" {
		return nil, fmt.Errorf("IPC auth token is empty")
	}
	return ipc.NewControlClientWithToken(ctx, socketPath, token)
}

// controlCmd holds the offline key and token tools. None contact the daemon.
func controlCmd() *cobra.Command {
	root := &cobra.Command{Use: "control", Short: "Offline signing keys and tokens for stopping or upgrading darkd"}

	var outDir string
	keygen := &cobra.Command{
		Use:   "keygen --out <dir>",
		Short: "Generate an Ed25519 control signing key pair (offline)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if outDir == "" {
				return fmt.Errorf("--out is required")
			}
			privPath, pubPath, pub, err := control.GenerateKeyPair(outDir)
			if err != nil {
				return err
			}
			_, err = fmt.Fprintf(cmd.OutOrStdout(), "private key: %s (keep offline, mode 0600)\npublic key:  %s\nfingerprint: %s\n", privPath, pubPath, control.Fingerprint(pub))
			return err
		},
	}
	keygen.Flags().StringVar(&outDir, "out", "", "directory for the new key pair; existing files are never overwritten")
	root.AddCommand(keygen)

	var keyPath, systemID, action string
	var ttl time.Duration
	sign := &cobra.Command{
		Use:   "sign-stop --key <priv> --system-id <id> --action stop|upgrade [--ttl 10m]",
		Short: "Sign a single-use stop or upgrade token (offline)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if keyPath == "" || systemID == "" {
				return fmt.Errorf("--key and --system-id are required")
			}
			priv, err := control.LoadPrivateKey(keyPath)
			if err != nil {
				return err
			}
			claims, err := control.NewClaims(action, systemID, time.Now(), ttl)
			if err != nil {
				return err
			}
			token, err := control.SignToken(priv, claims)
			if err != nil {
				return err
			}
			_, err = fmt.Fprintln(cmd.OutOrStdout(), token)
			return err
		},
	}
	sign.Flags().StringVar(&keyPath, "key", "", "private key written by 'control keygen'")
	sign.Flags().StringVar(&systemID, "system-id", "", "target endpoint system ID (printed by 'sudo -H afterdark-darkd status' on the endpoint)")
	sign.Flags().StringVar(&action, "action", "", "stop or upgrade")
	sign.Flags().DurationVar(&ttl, "ttl", 10*time.Minute, "token lifetime, at most 15m")
	root.AddCommand(sign)
	return root
}
