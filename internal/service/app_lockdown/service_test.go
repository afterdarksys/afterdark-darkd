package app_lockdown

import (
	"testing"
	"time"
)

func TestConfigureDoesNotDeadlockOrClaimEnforcement(t *testing.T) {
	s, _ := New(nil, nil)
	done := make(chan error, 1)
	go func() { done <- s.Configure(&Config{BlockNewProcesses: true}) }()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("unsupported enforcement accepted")
		}
	case <-time.After(time.Second):
		t.Fatal("configure deadlocked")
	}
	if err := s.Configure(&Config{}); err != nil {
		t.Fatal(err)
	}
}
