package protector

import (
	"context"
	"os"
	"testing"
	"time"
)

func TestProcessSnapshotContainsSelf(t *testing.T) {
	rows, err := processSnapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range rows {
		if row["pid"] == int32(os.Getpid()) && row["name"] != "" {
			return
		}
	}
	t.Fatal("self missing from real process snapshot")
}
func TestRemoteResponseRequiresLocalAuthorization(t *testing.T) {
	s := NewService(&Config{}, nil)
	defer s.cancel()
	for _, kind := range []string{"kill_process", "block_connection"} {
		if _, err := s.handleCommand(Command{ID: "fixture", Timestamp: time.Now(), Type: kind}); err == nil {
			t.Fatal("mutation enabled by default")
		}
	}
	if _, err := s.handleCommand(Command{ID: "old", Timestamp: time.Now().Add(-time.Hour), Type: "collect_forensics"}); err == nil {
		t.Fatal("expired command accepted")
	}
	if _, err := s.evidence("behavior_analysis"); err == nil {
		t.Fatal("missing behavior service returned fabricated risk")
	}
}

func TestStopWithConcurrentProducers(t *testing.T) {
	s := NewService(&Config{Enabled: true}, nil)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 100; i++ {
			s.QueueAlert(Alert{})
			s.QueueTelemetry("fixture", i)
		}
	}()
	if err := s.Stop(); err != nil {
		t.Fatal(err)
	}
	<-done
	s.QueueAlert(Alert{})
	s.QueueTelemetry("fixture", nil)
	if err := s.Stop(); err != nil {
		t.Fatal(err)
	}
}

func TestProtectorRejectsInsecureRemoteAndDefaultsIntervals(t *testing.T) {
	s := NewService(&Config{ProtectorURL: "ws://example.com/socket"}, nil)
	defer s.cancel()
	if s.config.HeartbeatInterval <= 0 || s.config.ReconnectDelay <= 0 {
		t.Fatal("invalid defaults")
	}
	if err := s.connect(); err == nil {
		t.Fatal("insecure remote accepted")
	}
}
