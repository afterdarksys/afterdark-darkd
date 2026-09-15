//go:build windows

package ipc

import (
	"context"
	pb "github.com/afterdarksys/afterdark-darkd/api/proto/ipc"
	"github.com/google/uuid"
	"testing"
	"time"
)

func TestWindowsPipeRoundTrip(t *testing.T) {
	name := `\\.\pipe\darkd-test-` + uuid.NewString()
	s, err := New(&Config{PipeName: name}, nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err = s.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer s.Stop(ctx)
	conn, err := Dial(ctx, name)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err = pb.NewDaemonServiceClient(conn).GetStatus(ctx, &pb.StatusRequest{}); err != nil {
		t.Fatal(err)
	}
}
