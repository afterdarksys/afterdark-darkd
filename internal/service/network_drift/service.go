package network_drift

import (
	"context"
	"sync"
	"time"

	"github.com/afterdarksys/afterdark-darkd/internal/service"
	"github.com/afterdarksys/afterdark-darkd/pkg/logging"
	"go.uber.org/zap"
)

const ServiceName = "network_drift"

type Config struct {
	Enabled      bool          `mapstructure:"enabled"`
	ScanInterval time.Duration `mapstructure:"scan_interval"`
}

type Service struct {
	config   *Config
	logger   *zap.Logger
	registry service.RegistryInterface

	baselinePorts map[int]string // port -> procName
	mu            sync.RWMutex
	running       bool
	stopCh        chan struct{}
}

func New(config *Config, registry service.RegistryInterface) (*Service, error) {
	if config == nil {
		config = &Config{
			Enabled:      true,
			ScanInterval: 5 * time.Minute,
		}
	}

	return &Service{
		config:        config,
		logger:        logging.With(zap.String("service", ServiceName)),
		registry:      registry,
		baselinePorts: make(map[int]string),
		stopCh:        make(chan struct{}),
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

	s.logger.Info("starting network_drift service")
	go s.monitorLoop()

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
	s.logger.Info("stopped network_drift service")
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
	return service.HealthStatus{
		Status:    service.HealthHealthy,
		Message:   "monitoring active",
		LastCheck: time.Now(),
	}
}

func (s *Service) monitorLoop() {
	ticker := time.NewTicker(s.config.ScanInterval)
	defer ticker.Stop()

	// Capture initial baseline
	s.scanPorts()

	for {
		select {
		case <-s.stopCh:
			return
		case <-ticker.C:
			s.scanPorts()
		}
	}
}

func (s *Service) scanPorts() {
	// STUB: Real implementation would use gopsutil/net to get listening ports
	// and compare against s.baselinePorts
}
