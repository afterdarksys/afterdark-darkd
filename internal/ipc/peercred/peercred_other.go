//go:build !darwin && !linux

package peercred

import (
	"fmt"
	"net"
)

func FromConn(net.Conn) (uint32, error) {
	return 0, fmt.Errorf("peer credentials are not supported on this platform")
}
