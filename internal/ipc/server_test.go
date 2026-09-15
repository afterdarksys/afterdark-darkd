package ipc

import (
	"context"
	pb "github.com/afterdarksys/afterdark-darkd/api/proto/ipc"
	"github.com/afterdarksys/afterdark-darkd/internal/service"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"testing"
)

func TestUnavailableOperations(t *testing.T) {
	s := &Server{}
	ctx := context.Background()
	if _, err := s.StopService(ctx, &pb.ServiceRequest{Name: "missing"}); status.Code(err) != codes.Unimplemented {
		t.Fatal(err)
	}
	if _, err := s.CheckBulk(ctx, &pb.CheckBulkRequest{Domains: []string{"example.com"}}); status.Code(err) != codes.Unavailable {
		t.Fatal(err)
	}
	s.registry = service.NewRegistry()
	if _, err := s.TriggerScan(ctx, &pb.TriggerScanRequest{ScanType: "bogus"}); status.Code(err) != codes.InvalidArgument {
		t.Fatal(err)
	}
}
