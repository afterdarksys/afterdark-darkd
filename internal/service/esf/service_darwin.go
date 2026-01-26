//go:build darwin

package esf

import (
	"context"
	"sync"
	"time"

	"github.com/afterdarksys/afterdark-darkd/internal/platform/darwin/esf"
	"github.com/afterdarksys/afterdark-darkd/internal/service"
	"github.com/afterdarksys/afterdark-darkd/pkg/logging"
	"go.uber.org/zap"
)

const ServiceName = "esf_monitor"

type Config struct {
	Enabled bool `mapstructure:"enabled"`
}

type Service struct {
	config   *Config
	logger   *zap.Logger
	registry service.RegistryInterface

	client *esf.Client

	mu      sync.RWMutex
	running bool
}

func New(config *Config, registry service.RegistryInterface) (*Service, error) {
	if config == nil {
		config = &Config{Enabled: true}
	}

	return &Service{
		config:   config,
		logger:   logging.With(zap.String("service", ServiceName)),
		registry: registry,
	}, nil
}

func (s *Service) Name() string {
	return ServiceName
}

func (s *Service) Start(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.running {
		return nil
	}

	client, err := esf.NewClient()
	if err != nil {
		// ESF requires special entitlements, so this might fail often in dev
		s.logger.Warn("failed to initialize ESF client (missing entitlements?)", zap.Error(err))
		// We return successfully so we don't crash the daemon, but service is "unhealthy"
		return nil
	}

	if err := client.Subscribe(); err != nil {
		s.logger.Error("failed to subscribe to ESF events", zap.Error(err))
		return nil
	}

	// Start handling events
	client.Start(func(evt esf.Event) {
		s.handleEvent(evt)
	})
	s.client = client
	s.running = true
	s.logger.Info("started ESF monitor")

	return nil
}

func (s *Service) handleEvent(evt esf.Event) {
	// Log the event for now
	s.logger.Info("ESF Event",
		zap.Int("type", int(evt.Type)),
		zap.Int("pid", evt.PID),
		zap.String("path", evt.Path))

	// Future: Send to SIEM or Process Monitor
}

func (s *Service) Stop(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.running || s.client == nil {
		return nil
	}

	s.client.Stop()
	s.running = false
	s.logger.Info("stopped ESF monitor")
	return nil
}

func (s *Service) Configure(config interface{}) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if cfg, ok := config.(*Config); ok {
		s.config = cfg
	}
	return nil
}

func (s *Service) Health() service.HealthStatus {
	s.mu.RLock()
	defer s.mu.RUnlock()

	status := service.HealthHealthy
	msg := "ESF active"

	if !s.running {
		status = service.HealthUnhealthy
		msg = "service stopped"
	} else if s.client == nil {
		status = service.HealthUnhealthy
		msg = "client failed to init"
	}

	return service.HealthStatus{
		Status:    status,
		Message:   msg,
		LastCheck: time.Now(),
	}
}
