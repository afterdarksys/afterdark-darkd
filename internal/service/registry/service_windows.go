//go:build windows

package registry

import (
	"context"
	"time"

	"github.com/afterdarksys/afterdark-darkd/internal/service"
	"go.uber.org/zap"
)

const ServiceName = "registry_monitor"

type Config struct {
	Enabled  bool          `mapstructure:"enabled"`
	Interval time.Duration `mapstructure:"interval"`
}

type Service struct {
	config *Config
	logger *zap.Logger
}

func New(config *Config, registry service.RegistryInterface) (*Service, error) {
	if config.Interval == 0 {
		config.Interval = 30 * time.Second
	}
	return &Service{
		config: config,
		logger: zap.NewExample(), // Placeholder
	}, nil
}

func (s *Service) Name() string {
	return ServiceName
}

func (s *Service) Start(ctx context.Context) error {
	s.logger.Info("Starting registry monitor")
	go s.runLoop(ctx)
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
		Message:   "running",
		LastCheck: time.Now(),
	}
}

func (s *Service) runLoop(ctx context.Context) {
	ticker := time.NewTicker(s.config.Interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.checkPersistence()
		}
	}
}

func (s *Service) checkPersistence() {
	// TODO: Implement registry polling using golang.org/x/sys/windows/registry
	// s.logger.Info("Polling registry persistence keys...")
}
