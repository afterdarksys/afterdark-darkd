//go:build !windows

package ipc

import (
	"context"
	"fmt"
	"google.golang.org/grpc"
	"net"
)

func (s *Server) createWindowsListener() (net.Listener, error) {
	return nil, fmt.Errorf("Windows pipes unsupported")
}
func dialWindowsPipe(context.Context, string) (*grpc.ClientConn, error) {
	return nil, fmt.Errorf("Windows pipes unsupported")
}
