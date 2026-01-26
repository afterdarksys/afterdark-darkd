//go:build !windows

package registry

import (
	"context"
	"time"

	"github.com/afterdarksys/afterdark-darkd/internal/service"
)

const ServiceName = "registry_monitor"

type Config struct {
	Enabled  bool          `mapstructure:"enabled"`
	Interval time.Duration `mapstructure:"interval"`
}

type Service struct{}

func New(config *Config, registry service.RegistryInterface) (*Service, error) {
	return &Service{}, nil
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
		Status:    service.HealthHealthy,
		Message:   "platform not supported",
		LastCheck: time.Now(),
	}
}
