package plugin

import (
	"context"
	pb "github.com/afterdarksys/afterdark-darkd/api/proto/plugin"
	"testing"
)

type lifecycleFixture struct {
	ctx    context.Context
	starts int
}

func (p *lifecycleFixture) Info() PluginInfo                       { return PluginInfo{Name: "fixture"} }
func (p *lifecycleFixture) Configure(map[string]interface{}) error { return nil }
func (p *lifecycleFixture) Start(ctx context.Context) error        { p.ctx = ctx; p.starts++; return nil }
func (p *lifecycleFixture) Stop(context.Context) error             { return nil }
func (p *lifecycleFixture) Health() PluginHealth                   { return PluginHealth{} }
func (p *lifecycleFixture) Execute(context.Context, string, map[string]interface{}) (map[string]interface{}, error) {
	return nil, nil
}
func TestServiceLifetimeOutlivesStartRPC(t *testing.T) {
	p := &lifecycleFixture{}
	s := &serviceGRPCServer{Impl: p}
	request, cancel := context.WithCancel(context.Background())
	response, err := s.Start(request, &pb.ServiceStartRequest{})
	if err != nil || !response.Success {
		t.Fatalf("start: %v %v", response, err)
	}
	cancel()
	if p.ctx.Err() != nil {
		t.Fatal("service canceled when Start RPC returned")
	}
	if _, err := s.Start(context.Background(), &pb.ServiceStartRequest{}); err != nil {
		t.Fatal(err)
	}
	if p.starts != 1 {
		t.Fatal("duplicate start")
	}
	responseStop, err := s.Stop(context.Background(), &pb.ServiceStopRequest{})
	if err != nil || !responseStop.Success {
		t.Fatalf("stop: %v %v", responseStop, err)
	}
	if p.ctx.Err() != context.Canceled {
		t.Fatal("Stop failed to cancel service context")
	}
}
