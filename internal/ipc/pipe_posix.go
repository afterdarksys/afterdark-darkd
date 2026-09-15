//go:build !windows

package ipc

import (
	"context"
	"fmt"
	"google.golang.org/grpc"
)

func dialWindowsPipe(context.Context, string, ...grpc.DialOption) (*grpc.ClientConn, error) {
	return nil, fmt.Errorf("Windows pipes unsupported")
}
