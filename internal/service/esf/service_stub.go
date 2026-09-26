//go:build !darwin

package esf

import (
	"context"
	"time"

	"github.com/afterdarksys/afterdark-darkd/internal/service"
	"go.uber.org/zap"
)

const ServiceName = "esf_monitor"

type Config struct {
	Enabled bool `mapstructure:"enabled"`
	// Maintenance reports whether a signed control token opened the stop
	// window. It is read on every auth callback and must not block. Nil
	// means the window is always closed.
	Maintenance func() bool `mapstructure:"-" yaml:"-" json:"-"`
}

type Service struct {
	logger *zap.Logger
}

func New(config *Config, registry service.RegistryInterface) (*Service, error) {
	return &Service{
		logger: zap.NewExample(),
	}, nil
}

func (s *Service) Name() string {
	return ServiceName
}

func (s *Service) Start(ctx context.Context) error {
	return nil
}

func (s *Service) Stop(ctx context.Context) error {
	return nil
}

func (s *Service) Configure(config interface{}) error {
	return nil
}

func (s *Service) Health() service.HealthStatus {
	return service.HealthStatus{
		Status:    service.HealthDegraded,
		Message:   "platform not supported",
		LastCheck: time.Now(),
	}
}
