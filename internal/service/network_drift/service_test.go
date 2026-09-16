package network_drift

import (
	"context"
	"errors"
	gnet "github.com/shirou/gopsutil/v3/net"
	"testing"
	"time"
)

func TestListenerSnapshotsDoNotInventDriftOnStartupOrFailedCollection(t *testing.T) {
	s, _ := New(&Config{ScanInterval: time.Minute}, nil)
	ctx := context.Background()
	rows := []gnet.ConnectionStat{{Status: "LISTEN", Laddr: gnet.Addr{IP: "127.0.0.1", Port: 22}, Pid: 10}}
	var collectErr error
	var events []listener
	reject := false
	s.collect = func(context.Context) ([]gnet.ConnectionStat, error) { return rows, collectErr }
	s.emit = func(_ context.Context, l listener) error {
		if reject {
			return errors.New("queue full")
		}
		events = append(events, l)
		return nil
	}
	s.scan(ctx)
	s.scan(ctx)
	if len(events) != 0 {
		t.Fatal("startup or unchanged snapshot produced alert")
	}
	collectErr = errors.New("permission denied")
	rows = nil
	s.scan(ctx)
	if len(s.baseline) != 1 {
		t.Fatal("failed scan erased baseline")
	}
	collectErr = nil
	rows = []gnet.ConnectionStat{{Status: "LISTEN", Laddr: gnet.Addr{IP: "0.0.0.0", Port: 8080}, Pid: 11}, {Status: "ESTABLISHED", Laddr: gnet.Addr{Port: 40000}, Pid: 12}}
	reject = true
	s.scan(ctx)
	if len(events) != 0 || s.lastErr == nil {
		t.Fatal("failed event delivery not reported")
	}
	reject = false
	s.scan(ctx)
	s.scan(ctx)
	if len(events) != 1 || events[0].Port != 8080 {
		t.Fatal("listener retry/dedup failed", events)
	}
}
