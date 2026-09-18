// Package coverage publishes local endpoint sensor coverage independently of
// telemetry forwarding. It is intentionally read-only.
package coverage

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/afterdarksys/afterdark-darkd/internal/events"
	"github.com/afterdarksys/afterdark-darkd/internal/service"
	"github.com/afterdarksys/afterdark-darkd/internal/service/siem"
)

const ServiceName = "sensor_coverage"

type Service struct {
	registry       service.RegistryInterface
	deploymentMode string
	collector      func(context.Context, *events.Store, service.RegistryInterface, string) error
	mu             sync.Mutex
	cancel         context.CancelFunc
	done           chan struct{}
	lastSuccess    time.Time
	lastErr        error
}

func New(registry service.RegistryInterface, deploymentMode string) *Service {
	return &Service{registry: registry, deploymentMode: deploymentMode, collector: siem.CollectCoverage}
}
func (s *Service) Name() string { return ServiceName }
func (s *Service) Configure(interface{}) error {
	return fmt.Errorf("sensor coverage configuration requires restart")
}

func (s *Service) Start(ctx context.Context) error {
	s.mu.Lock()
	if s.cancel != nil {
		s.mu.Unlock()
		return nil
	}
	store, ok := s.registry.Get(events.ServiceName).(*events.Store)
	if !ok {
		s.mu.Unlock()
		return fmt.Errorf("durable event store required for sensor coverage")
	}
	ctx, s.cancel = context.WithCancel(ctx)
	s.done = make(chan struct{})
	s.mu.Unlock()
	s.collect(ctx, store)
	go func() {
		defer close(s.done)
		ticker := time.NewTicker(time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				s.collect(ctx, store)
			}
		}
	}()
	return nil
}

func (s *Service) collect(ctx context.Context, store *events.Store) {
	collectionCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	err := s.collector(collectionCtx, store, s.registry, s.deploymentMode)
	cancel()
	s.mu.Lock()
	defer s.mu.Unlock()
	if err != nil {
		s.lastErr = err
		return
	}
	s.lastErr = nil
	s.lastSuccess = time.Now().UTC()
}

func (s *Service) Stop(ctx context.Context) error {
	s.mu.Lock()
	cancel, done := s.cancel, s.done
	s.mu.Unlock()
	if cancel == nil {
		return nil
	}
	cancel()
	select {
	case <-done:
		s.mu.Lock()
		s.cancel, s.done = nil, nil
		s.mu.Unlock()
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (s *Service) Health() service.HealthStatus {
	s.mu.Lock()
	defer s.mu.Unlock()
	status, message := service.HealthHealthy, "local sensor coverage active"
	if s.cancel == nil {
		status, message = service.HealthUnhealthy, "sensor coverage stopped"
	} else if s.lastErr != nil {
		status, message = service.HealthDegraded, s.lastErr.Error()
	} else if s.lastSuccess.IsZero() {
		status, message = service.HealthUnknown, "waiting for initial coverage collection"
	}
	return service.HealthStatus{Status: status, Message: message, LastCheck: time.Now(), Metrics: map[string]any{"last_success": s.lastSuccess}}
}
