package service

import (
	"context"
	"errors"
	"testing"
)

type testService struct {
	name string
	fail bool
	log  *[]string
}

func (s *testService) Name() string { return s.name }
func (s *testService) Start(context.Context) error {
	*s.log = append(*s.log, "start:"+s.name)
	if s.fail {
		return errors.New("failed")
	}
	return nil
}
func (s *testService) Stop(context.Context) error {
	*s.log = append(*s.log, "stop:"+s.name)
	return nil
}
func (s *testService) Configure(interface{}) error { return nil }
func (s *testService) Health() HealthStatus        { return HealthStatus{Status: HealthHealthy} }
func TestStartupRollback(t *testing.T) {
	var log []string
	r := NewRegistry()
	r.Register(&testService{"a", false, &log})
	r.Register(&testService{"b", true, &log})
	r.Register(&testService{"c", false, &log})
	if r.StartAll(context.Background()) == nil {
		t.Fatal("expected failure")
	}
	want := []string{"start:a", "start:b", "stop:b", "stop:a"}
	if len(log) != len(want) {
		t.Fatal(log)
	}
	for i := range want {
		if log[i] != want[i] {
			t.Fatal(log)
		}
	}
	r.StopAll(context.Background())
	if len(log) != len(want) {
		t.Fatal("stop repeated", log)
	}
}
