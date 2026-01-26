package app_lockdown

import (
	"context"
	"sync"
	"time"

	"github.com/afterdarksys/afterdark-darkd/internal/service"
	"github.com/afterdarksys/afterdark-darkd/pkg/logging"
	"go.uber.org/zap"
)

const ServiceName = "app_lockdown"

type Config struct {
	Enabled           bool     `mapstructure:"enabled"`
	Allowlist         []string `mapstructure:"allowlist"`
	BlockNewProcesses bool     `mapstructure:"block_new_processes"`
}

type Service struct {
	config   *Config
	logger   *zap.Logger
	registry service.RegistryInterface

	mu      sync.RWMutex
	running bool
	locked  bool
	stopCh  chan struct{}
}

func New(config *Config, registry service.RegistryInterface) (*Service, error) {
	if config == nil {
		config = &Config{
			Enabled:   false, // Default off for safety
			Allowlist: []string{"/usr/sbin/sshd", "/usr/bin/bash"},
		}
	}

	return &Service{
		config:   config,
		logger:   logging.With(zap.String("service", ServiceName)),
		registry: registry,
		stopCh:   make(chan struct{}),
	}, nil
}

func (s *Service) Name() string {
	return ServiceName
}

func (s *Service) Start(ctx context.Context) error {
	s.mu.Lock()
	if s.running {
		s.mu.Unlock()
		return nil
	}
	s.running = true
	s.mu.Unlock()

	s.logger.Info("starting app_lockdown service")

	if s.config.BlockNewProcesses {
		s.EnableLockdown()
	}

	return nil
}

func (s *Service) Stop(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.running {
		return nil
	}
	s.running = false
	close(s.stopCh)
	s.logger.Info("stopped app_lockdown service")
	return nil
}

func (s *Service) Configure(config interface{}) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if cfg, ok := config.(*Config); ok {
		s.config = cfg
		if cfg.BlockNewProcesses {
			s.EnableLockdown()
		} else {
			s.DisableLockdown()
		}
	}
	return nil
}

func (s *Service) EnableLockdown() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.locked = true
	s.logger.Warn("LOCKDOWN MODE ENABLED: Blocking all new processes not in allowlist")
	// STUB: Enable kernel restrictions (e.g., via Fanotify or process hooks)
}

func (s *Service) DisableLockdown() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.locked = false
	s.logger.Info("Lockdown mode disabled")
}

func (s *Service) Health() service.HealthStatus {
	status := service.HealthHealthy
	msg := "ready"
	if s.locked {
		status = service.HealthDegraded // Warning state
		msg = "LOCKDOWN ACTIVE"
	}

	return service.HealthStatus{
		Status:    status,
		Message:   msg,
		LastCheck: time.Now(),
	}
}
