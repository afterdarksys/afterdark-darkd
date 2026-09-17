package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"runtime"
	"strings"
	"time"

	pb "github.com/afterdarksys/afterdark-darkd/api/proto/ipc"
	cloud "github.com/afterdarksys/afterdark-darkd/internal/api/darkapi"
	"github.com/afterdarksys/afterdark-darkd/internal/ipc"
	"github.com/google/uuid"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

var Version, Commit, BuildTime = "dev", "unknown", "unknown"

type options struct {
	baseURL, credentials, socket string
	timeout                      time.Duration
}

func main() {
	if err := newRoot().Execute(); err != nil {
		os.Exit(1)
	}
}
func newRoot() *cobra.Command {
	o := &options{}
	root := &cobra.Command{Use: "darkapi", Short: "DarkAPI account, device, and endpoint administration", SilenceUsage: true, Version: fmt.Sprintf("%s (%s)", Version, Commit)}
	root.PersistentFlags().StringVar(&o.baseURL, "url", os.Getenv("DARKAPI_URL"), "API base URL (default https://api.darkapi.io)")
	root.PersistentFlags().StringVar(&o.credentials, "credentials", cloud.DefaultCredentialPath(), "protected account/device credential file")
	root.PersistentFlags().StringVar(&o.socket, "socket", "", "local daemon socket or Windows pipe")
	root.PersistentFlags().DurationVar(&o.timeout, "timeout", 30*time.Second, "overall command timeout")
	output := func(cmd *cobra.Command, value interface{}) error {
		e := json.NewEncoder(cmd.OutOrStdout())
		e.SetIndent("", "  ")
		return e.Encode(value)
	}
	call := func(fn func(context.Context, *cloud.Client) (interface{}, error)) func(*cobra.Command, []string) error {
		return func(cmd *cobra.Command, _ []string) error {
			client, _, err := o.client()
			if err != nil {
				return err
			}
			ctx, cancel := context.WithTimeout(cmd.Context(), o.timeout)
			defer cancel()
			value, err := fn(ctx, client)
			if err != nil {
				return err
			}
			return output(cmd, value)
		}
	}
	auth := &cobra.Command{Use: "auth", Short: "Authenticate an account"}
	auth.AddCommand(&cobra.Command{Use: "status", Short: "Verify account credentials with the API", RunE: call(func(ctx context.Context, c *cloud.Client) (interface{}, error) { return c.Account(ctx) })})
	var email string
	login := &cobra.Command{Use: "login", Short: "Authenticate with email and save the returned credential", RunE: func(cmd *cobra.Command, _ []string) error {
		client, saved, err := o.client()
		if err != nil {
			return err
		}
		password := os.Getenv("DARKAPI_PASSWORD")
		if password == "" {
			if !term.IsTerminal(int(os.Stdin.Fd())) {
				return fmt.Errorf("set DARKAPI_PASSWORD for non-interactive login")
			}
			fmt.Fprint(cmd.ErrOrStderr(), "Password: ")
			b, err := term.ReadPassword(int(os.Stdin.Fd()))
			fmt.Fprintln(cmd.ErrOrStderr())
			if err != nil {
				return err
			}
			password = string(b)
		}
		ctx, cancel := context.WithTimeout(cmd.Context(), o.timeout)
		defer cancel()
		result, err := client.Login(ctx, email, password)
		if err != nil {
			return err
		}
		saved.APIKey = result.APIKey
		if err := cloud.SaveCredentials(o.credentials, saved); err != nil {
			return err
		}
		fmt.Fprintln(cmd.OutOrStdout(), "Account credential saved.")
		return nil
	}}
	login.Flags().StringVar(&email, "email", "", "account email")
	login.MarkFlagRequired("email")
	auth.AddCommand(login)
	root.AddCommand(auth)
	root.AddCommand(integrationsCmd())
	root.AddCommand(&cobra.Command{Use: "health", Short: "Check API connectivity (does not verify authentication)", RunE: call(func(ctx context.Context, c *cloud.Client) (interface{}, error) {
		err := c.Health(ctx)
		return map[string]bool{"reachable": err == nil}, err
	})})
	root.AddCommand(&cobra.Command{Use: "account", Short: "Fetch authenticated account details", RunE: call(func(ctx context.Context, c *cloud.Client) (interface{}, error) { return c.Account(ctx) })})
	device := &cobra.Command{Use: "device", Short: "Enroll and manage this device"}
	device.AddCommand(&cobra.Command{Use: "enroll", Short: "Exchange an enrollment token or write-enabled account key for device credentials", RunE: func(cmd *cobra.Command, _ []string) error {
		client, saved, err := o.client()
		if err != nil {
			return err
		}
		if saved.DeviceID != "" {
			return fmt.Errorf("device already enrolled; use a new credential file for a new enrollment")
		}
		hostname, err := os.Hostname()
		if err != nil {
			return err
		}
		ctx, cancel := context.WithTimeout(cmd.Context(), o.timeout)
		defer cancel()
		result, err := client.Enroll(ctx, cloud.EnrollmentRequest{EnrollmentToken: os.Getenv("DARKAPI_ENROLLMENT_TOKEN"), Hostname: hostname, Platform: runtime.GOOS, Architecture: runtime.GOARCH, AgentVersion: Version})
		if err != nil {
			return err
		}
		saved.DeviceID = result.DeviceID
		saved.DeviceKey = result.APIKey
		if err := cloud.SaveCredentials(o.credentials, saved); err != nil {
			return fmt.Errorf("device enrolled but credential persistence failed: %w", err)
		}
		return output(cmd, map[string]string{"device_id": result.DeviceID, "credentials": o.credentials})
	}})
	device.AddCommand(&cobra.Command{Use: "rotate", Short: "Rotate the device credential safely; restart darkd afterward", RunE: func(cmd *cobra.Command, _ []string) error {
		client, _, err := o.client()
		if err != nil {
			return err
		}
		ctx, cancel := context.WithTimeout(cmd.Context(), o.timeout)
		defer cancel()
		if err = client.RotateCredentials(ctx, o.credentials); err != nil {
			return err
		}
		return output(cmd, map[string]string{"status": "rotated", "next_step": "Restart darkd to load the new credential"})
	}})
	device.AddCommand(&cobra.Command{Use: "heartbeat", Short: "Send an authenticated device heartbeat", RunE: call(func(ctx context.Context, c *cloud.Client) (interface{}, error) {
		err := c.Heartbeat(ctx)
		return map[string]bool{"accepted": err == nil}, err
	})})
	device.AddCommand(&cobra.Command{Use: "config", Short: "Fetch device configuration for inspection", RunE: call(func(ctx context.Context, c *cloud.Client) (interface{}, error) { return c.DeviceConfig(ctx) })})
	var telemetryFile string
	telemetry := &cobra.Command{Use: "telemetry", Short: "Submit a telemetry JSON file with a stable UUID event_id", RunE: func(cmd *cobra.Command, _ []string) error {
		f, err := os.Open(telemetryFile)
		if err != nil {
			return err
		}
		defer f.Close()
		b, err := io.ReadAll(io.LimitReader(f, 1<<20+1))
		if err != nil {
			return err
		}
		if len(b) > 1<<20 {
			return fmt.Errorf("telemetry file exceeds 1 MiB")
		}
		var report cloud.TelemetryReport
		if err := json.Unmarshal(b, &report); err != nil {
			return err
		}
		if _, err := uuid.Parse(report.EventID); err != nil {
			return fmt.Errorf("file must contain a stable UUID event_id so retries can be deduplicated")
		}
		return call(func(ctx context.Context, c *cloud.Client) (interface{}, error) {
			err := c.ReportTelemetry(ctx, &report)
			return map[string]string{"event_id": report.EventID, "status": "accepted"}, err
		})(cmd, nil)
	}}
	telemetry.Flags().StringVar(&telemetryFile, "file", "", "telemetry JSON file")
	telemetry.MarkFlagRequired("file")
	device.AddCommand(telemetry)
	root.AddCommand(device)
	check := &cobra.Command{Use: "check", Short: "Query live DarkAPI reputation"}
	for _, kind := range []string{"domain", "ip", "hash", "url", "email"} {
		kind := kind
		check.AddCommand(&cobra.Command{Use: kind + " <indicator>", Args: cobra.ExactArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
			return call(func(ctx context.Context, c *cloud.Client) (interface{}, error) {
				if kind == "ip" {
					return c.LookupIP(ctx, args[0])
				}
				return c.Lookup(ctx, args[0], kind)
			})(cmd, nil)
		}})
	}
	check.AddCommand(&cobra.Command{Use: "bulk <indicator>...", Args: cobra.RangeArgs(1, 100), RunE: func(cmd *cobra.Command, args []string) error {
		return call(func(ctx context.Context, c *cloud.Client) (interface{}, error) {
			return c.BulkLookup(ctx, &cloud.BulkLookupRequest{Domains: args})
		})(cmd, nil)
	}})
	root.AddCommand(check)
	for _, name := range []string{"status", "patches", "report"} {
		name := name
		root.AddCommand(&cobra.Command{Use: name, Short: "Read " + name + " from the local daemon", RunE: func(cmd *cobra.Command, _ []string) error {
			ctx, cancel := context.WithTimeout(cmd.Context(), o.timeout)
			defer cancel()
			conn, err := ipc.Dial(ctx, o.socket)
			if err != nil {
				return err
			}
			defer conn.Close()
			client := pb.NewDaemonServiceClient(conn)
			var result interface{}
			switch name {
			case "status":
				result, err = client.GetHealth(ctx, &pb.HealthRequest{})
			case "patches":
				result, err = client.GetCompliance(ctx, &pb.GetComplianceRequest{})
			case "report":
				result, err = client.GetEvents(ctx, &pb.GetEventsRequest{})
			}
			if err != nil {
				return err
			}
			return output(cmd, result)
		}})
	}
	var requestFile string
	requestCmd := &cobra.Command{Use: "request <method> </v1/path>", Short: "Call another account-authenticated API endpoint", Args: cobra.ExactArgs(2), RunE: func(cmd *cobra.Command, args []string) error {
		var body json.RawMessage
		if requestFile != "" {
			f, err := os.Open(requestFile)
			if err != nil {
				return err
			}
			defer f.Close()
			body, err = io.ReadAll(io.LimitReader(f, (1<<20)+1))
			if err != nil {
				return err
			}
			if len(body) > 1<<20 {
				return fmt.Errorf("request file exceeds 1 MiB")
			}
		}
		return call(func(ctx context.Context, c *cloud.Client) (interface{}, error) {
			return c.AccountRequest(ctx, args[0], args[1], body)
		})(cmd, nil)
	}}
	requestCmd.Flags().StringVar(&requestFile, "file", "", "optional JSON request body")
	root.AddCommand(requestCmd)
	return root
}
func (o *options) client() (*cloud.Client, *cloud.Credentials, error) {
	saved := &cloud.Credentials{}
	path := ""
	if _, err := os.Lstat(o.credentials); err == nil {
		var e error
		saved, e = cloud.LoadCredentials(o.credentials)
		if e != nil {
			return nil, nil, e
		}
		path = o.credentials
	} else if !os.IsNotExist(err) {
		return nil, nil, err
	}
	base := o.baseURL
	if base == "" {
		base = saved.BaseURL
	}
	normalized, err := cloud.NormalizeURL(base, false)
	if err != nil {
		return nil, nil, err
	}
	c := cloud.New(&cloud.Config{BaseURL: normalized, APIKey: strings.TrimSpace(os.Getenv("DARKAPI_API_KEY")), CredentialFile: path, Timeout: o.timeout})
	if err := c.Validate(); err != nil {
		return nil, nil, err
	}
	saved.BaseURL = normalized
	return c, saved, nil
}
