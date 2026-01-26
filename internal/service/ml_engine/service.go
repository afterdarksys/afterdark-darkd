package ml_engine

import (
	"context"
	"sync"
	"time"

	"github.com/afterdarksys/afterdark-darkd/internal/service"
	"github.com/afterdarksys/afterdark-darkd/pkg/logging"
	"go.uber.org/zap"
)

const ServiceName = "ml_engine"

type Config struct {
	Enabled          bool          `mapstructure:"enabled"`
	TrainingInterval time.Duration `mapstructure:"training_interval"`
	ModelPath        string        `mapstructure:"model_path"`
}

type Service struct {
	config   *Config
	logger   *zap.Logger
	registry service.RegistryInterface

	// Models
	processModel *IsolationForest
	ubaModel     *IsolationForest

	// State
	mu      sync.RWMutex
	running bool
	stopCh  chan struct{}
}

func New(config *Config, registry service.RegistryInterface) (*Service, error) {
	if config == nil {
		config = &Config{
			Enabled:          true,
			TrainingInterval: 1 * time.Hour,
			ModelPath:        "/var/lib/afterdark/models",
		}
	}

	return &Service{
		config:   config,
		logger:   logging.With(zap.String("service", ServiceName)),
		registry: registry,
		stopCh:   make(chan struct{}),
		// Initialize models with default params
		processModel: NewIsolationForest(100, 256),
		ubaModel:     NewIsolationForest(100, 256),
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

	s.logger.Info("starting ml_engine service")

	go s.loop()

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
	s.logger.Info("stopped ml_engine service")
	return nil
}

func (s *Service) Health() service.HealthStatus {
	return service.HealthStatus{
		Status:    service.HealthHealthy,
		Message:   "models loaded",
		LastCheck: time.Now(),
	}
}

func (s *Service) loop() {
	ticker := time.NewTicker(s.config.TrainingInterval)
	defer ticker.Stop()

	for {
		select {
		case <-s.stopCh:
			return
		case <-ticker.C:
			s.trainModels()
		}
	}
}

func (s *Service) trainModels() {
	s.logger.Info("starting model retraining")
	// In a real implementation, we would fetch historical data from storage
	// and retrain the models.
	// For now, we simulate quick retraining.
	time.Sleep(100 * time.Millisecond)
	s.logger.Info("model retraining complete")
}

// Configure updates service configuration
func (s *Service) Configure(config interface{}) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if cfg, ok := config.(*Config); ok {
		s.config = cfg
		s.logger.Info("configuration updated",
			zap.Duration("training_interval", cfg.TrainingInterval),
			zap.Bool("enabled", cfg.Enabled))
	}
	return nil
}

// AnalyzeProcessScore returns an anomaly score for a process execution
func (s *Service) AnalyzeProcessScore(features []float64) float64 {
	return s.processModel.Score(features)
}
