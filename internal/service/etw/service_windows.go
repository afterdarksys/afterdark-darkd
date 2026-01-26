//go:build windows

package etw

import (
	"context"
	"time"

	"github.com/afterdarksys/afterdark-darkd/internal/platform/windows/etw"
	"github.com/afterdarksys/afterdark-darkd/internal/service"
	"github.com/afterdarksys/afterdark-darkd/pkg/logging"
	"go.uber.org/zap"
)

const ServiceName = "etw_monitor"

type Config struct {
	Enabled bool `mapstructure:"enabled"`
}

type Service struct {
	config   *Config
	logger   *zap.Logger
	registry service.RegistryInterface

	session *etw.Session
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
	s.logger.Info("Starting ETW monitor service")

	s.session = etw.NewSession("AfterDark-Kernel-Trace", s.logger)
	if err := s.session.Start(); err != nil {
		s.logger.Error("Failed to start ETW session", zap.Error(err))
		// Don't fail the whole daemon, just log error
		return nil
	}

	s.logger.Info("ETW session started successfully")
	return nil
}

func (s *Service) Stop(ctx context.Context) error {
	if s.session != nil {
		s.session.Stop()
	}
	s.logger.Info("ETW monitor service stopped")
	return nil
}

func (s *Service) Configure(config interface{}) error {
	return nil
}

func (s *Service) Health() service.HealthStatus {
	status := service.HealthHealthy
	msg := "ETW session active"

	// Basic check if session is active (simplified)
	if s.session == nil {
		status = service.HealthUnhealthy
		msg = "session not initialized"
	}

	return service.HealthStatus{
		Status:    status,
		Message:   msg,
		LastCheck: time.Now(),
	}
}
