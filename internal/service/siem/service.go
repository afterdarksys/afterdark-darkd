package siem

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"sync"
	"time"

	"github.com/afterdarksys/afterdark-darkd/internal/service"
	"github.com/afterdarksys/afterdark-darkd/pkg/logging"
	"go.uber.org/zap"
)

const ServiceName = "siem_forwarder"

type Config struct {
	Enabled   bool   `mapstructure:"enabled"`
	URL       string `mapstructure:"url"`
	AuthToken string `mapstructure:"auth_token"`
	BatchSize int    `mapstructure:"batch_size"`
}

type LogEvent struct {
	Timestamp time.Time `json:"timestamp"`
	Level     string    `json:"level"`
	Message   string    `json:"message"`
	Source    string    `json:"source"`
}

type Service struct {
	config   *Config
	logger   *zap.Logger
	registry service.RegistryInterface

	logChan chan LogEvent
	mu      sync.RWMutex
	running bool
	stopCh  chan struct{}
}

func New(config *Config, registry service.RegistryInterface) (*Service, error) {
	if config == nil {
		config = &Config{
			Enabled:   false,
			BatchSize: 100,
		}
	}

	return &Service{
		config:   config,
		logger:   logging.With(zap.String("service", ServiceName)),
		registry: registry,
		logChan:  make(chan LogEvent, 1000),
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

	s.logger.Info("starting siem forwarder")
	go s.forwardLoop()

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
	s.logger.Info("stopped siem forwarder")
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
		Message:   "forwarding active",
		LastCheck: time.Now(),
	}
}

// IngestLog is a public method for other services to send logs to SIEM
func (s *Service) IngestLog(level, msg, source string) {
	select {
	case s.logChan <- LogEvent{
		Timestamp: time.Now(),
		Level:     level,
		Message:   msg,
		Source:    source,
	}:
	default:
		// Drop log if buffer full to prevent blocking
	}
}

func (s *Service) forwardLoop() {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	var batch []LogEvent

	for {
		select {
		case <-s.stopCh:
			s.flush(batch)
			return
		case event := <-s.logChan:
			batch = append(batch, event)
			if len(batch) >= s.config.BatchSize {
				s.flush(batch)
				batch = nil
			}
		case <-ticker.C:
			if len(batch) > 0 {
				s.flush(batch)
				batch = nil
			}
		}
	}
}

func (s *Service) flush(batch []LogEvent) {
	if len(batch) == 0 || s.config.URL == "" {
		return
	}

	data, err := json.Marshal(batch)
	if err != nil {
		s.logger.Error("failed to marshal logs", zap.Error(err))
		return
	}

	req, err := http.NewRequest("POST", s.config.URL, bytes.NewBuffer(data))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")
	if s.config.AuthToken != "" {
		req.Header.Set("Authorization", "Bearer "+s.config.AuthToken)
	}

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		s.logger.Error("failed to forward logs to SIEM", zap.Error(err))
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		s.logger.Error("siem rejected logs", zap.Int("status", resp.StatusCode))
	}
}
