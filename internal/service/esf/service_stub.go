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
		Status:    service.HealthHealthy,
		Message:   "platform not supported",
		LastCheck: time.Now(),
	}
}
