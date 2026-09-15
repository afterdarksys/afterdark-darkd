//go:build windows

package ipc

import (
	"context"
	"github.com/Microsoft/go-winio"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"net"
	"strings"
)

func (s *Server) createWindowsListener() (net.Listener, error) {
	name := s.config.PipeName
	if !strings.HasPrefix(name, `\\.\pipe\`) {
		name = DefaultWindowsPipeName
	}
	return winio.ListenPipe(name, &winio.PipeConfig{SecurityDescriptor: "D:P(A;;GA;;;SY)(A;;GA;;;BA)", InputBufferSize: 65536, OutputBufferSize: 65536})
}
func dialWindowsPipe(ctx context.Context, name string) (*grpc.ClientConn, error) {
	opts := authDialOptions()
	opts = append(opts, grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) { return winio.DialPipeContext(ctx, name) }))
	return grpc.DialContext(ctx, "passthrough:///"+name, opts...)
}
