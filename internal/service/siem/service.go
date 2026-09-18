package siem

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/afterdarksys/afterdark-darkd/internal/api/darkapi"
	"github.com/afterdarksys/afterdark-darkd/internal/events"
	"github.com/afterdarksys/afterdark-darkd/internal/service"
	"net/http"
	"sync"
	"time"
)

const ServiceName = "siem_forwarder"

type Config struct {
	Routes         []Route `mapstructure:"routes"`
	DeploymentMode string
	DarkAPI        *darkapi.Client
	Enabled        bool   `mapstructure:"enabled"`
	URL            string `mapstructure:"url"`
	AuthToken      string `mapstructure:"auth_token"`
	BatchSize      int    `mapstructure:"batch_size"`
}
type Service struct {
	mu            sync.Mutex
	config        Config
	registry      service.RegistryInterface
	cancel        context.CancelFunc
	done          chan struct{}
	lastErr       error
	lastAuxErr    error
	lastHeartbeat time.Time
	client        *http.Client
}

func New(c *Config, r service.RegistryInterface) (*Service, error) {
	if c == nil {
		c = &Config{BatchSize: 100}
	}
	if c.BatchSize <= 0 || c.BatchSize > 1000 {
		c.BatchSize = 100
	}
	return &Service{config: *c, registry: r, client: &http.Client{Timeout: 5 * time.Second}}, nil
}
func (s *Service) Name() string { return ServiceName }
func (s *Service) Start(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cancel != nil {
		return nil
	}
	if err := s.validateRoutes(); err != nil {
		return err
	}
	if s.config.DarkAPI != nil && !s.config.DarkAPI.HasDeviceCredentials() {
		return fmt.Errorf("DarkAPI telemetry requires enrolled device credentials")
	}
	if _, ok := s.registry.Get(events.ServiceName).(*events.Store); !ok {
		return fmt.Errorf("durable event store required")
	}
	ctx, s.cancel = context.WithCancel(ctx)
	s.done = make(chan struct{})
	go s.run(ctx)
	return nil
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
		s.cancel = nil
		s.mu.Unlock()
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
func (s *Service) Configure(interface{}) error {
	return fmt.Errorf("SIEM configuration requires restart")
}
func (s *Service) Health() service.HealthStatus {
	s.mu.Lock()
	defer s.mu.Unlock()
	h := service.HealthStatus{Status: service.HealthHealthy, Message: "durable export active", LastCheck: time.Now()}
	if s.cancel == nil {
		h.Status = service.HealthUnhealthy
		h.Message = "export stopped"
	} else if s.lastErr != nil {
		h.Status = service.HealthDegraded
		h.Message = s.lastErr.Error()
	}
	if s.lastErr == nil && s.lastAuxErr != nil {
		h.Status = service.HealthDegraded
		h.Message = "coverage or command reporting failed"
	}
	return h
}
func (s *Service) IngestLog(level, msg, source string) {
	err := events.Emit(s.registry, source, "log", level, map[string]string{"message": msg})
	if err != nil {
		s.mu.Lock()
		s.lastErr = err
		s.mu.Unlock()
	}
}
func (s *Service) run(ctx context.Context) {
	defer close(s.done)
	delay := time.Second
	for {
		err := s.forward(ctx)
		s.mu.Lock()
		s.lastErr = err
		s.mu.Unlock()
		if err != nil {
			delay *= 2
			if delay > time.Minute {
				delay = time.Minute
			}
		} else {
			delay = time.Second
		}
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
	}
}
func (s *Service) forward(ctx context.Context) error {
	store := s.registry.Get(events.ServiceName).(*events.Store)
	if cloud := s.config.DarkAPI; cloud != nil && time.Since(s.lastHeartbeat) > time.Minute {
		commandErr := s.commands(ctx, store)
		s.mu.Lock()
		s.lastAuxErr = commandErr
		s.mu.Unlock()
		if err := cloud.Heartbeat(ctx); err != nil {
			return err
		}
		s.lastHeartbeat = time.Now()
	}
	batch, err := store.List(ctx, s.config.BatchSize, true, time.Time{}, "", "")
	if err != nil || len(batch) == 0 {
		return err
	}
	for _, route := range s.routes() {
		selected := make([]events.Event, 0, len(batch))
		for _, event := range batch {
			if matches(route, event) {
				selected = append(selected, event)
			}
		}
		if len(selected) > 0 {
			if err := s.deliver(ctx, route, selected); err != nil {
				return err
			}
		}
	}
	if cloud := s.config.DarkAPI; cloud != nil {
		for _, event := range batch {
			data, err := json.Marshal(event)
			if err != nil {
				return err
			}
			if err := cloud.ReportTelemetry(ctx, &darkapi.TelemetryReport{EventID: event.ID, Event: data}); err != nil {
				return err
			}
		}
	}
	ids := make([]string, len(batch))
	for i, e := range batch {
		ids[i] = e.ID
	}
	return store.Ack(ctx, ids)
}
