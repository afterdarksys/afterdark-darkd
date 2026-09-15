package ipc

import (
	"context"
	"google.golang.org/grpc"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

type clientToken string

func (t clientToken) GetRequestMetadata(context.Context, ...string) (map[string]string, error) {
	return map[string]string{"authorization": "Bearer " + string(t)}, nil
}

// Local sockets/pipes are protected by OS access control; TCP uses TLS.
func (clientToken) RequireTransportSecurity() bool { return false }
func authDialOptions() []grpc.DialOption {
	path := defaultTokenPath()
	data, err := os.ReadFile(path)
	if err != nil || len(strings.TrimSpace(string(data))) == 0 {
		return nil
	}
	return []grpc.DialOption{grpc.WithPerRPCCredentials(clientToken(strings.TrimSpace(string(data))))}
}

func defaultTokenPath() string {
	path := os.Getenv("AFTERDARK_AUTH_TOKEN_FILE")
	if path == "" {
		path = "/var/lib/afterdark/.auth_token"
		if runtime.GOOS == "windows" {
			base := os.Getenv("PROGRAMDATA")
			if base == "" {
				base = `C:\ProgramData`
			}
			path = filepath.Join(base, "AfterDark", ".auth_token")
		}
	}
	return path
}
