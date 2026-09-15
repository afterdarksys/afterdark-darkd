//go:build windows

package ipc

import (
	"context"
	"github.com/Microsoft/go-winio"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"net"
)

func dialWindowsPipe(ctx context.Context, name string, opts ...grpc.DialOption) (*grpc.ClientConn, error) {
	opts = append(opts, grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) { return winio.DialPipeContext(ctx, name) }))
	return grpc.DialContext(ctx, "passthrough:///"+name, opts...)
}
