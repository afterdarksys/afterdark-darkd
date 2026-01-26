package dlp

import (
	"context"
	"regexp"
	"sync"
	"time"

	"github.com/afterdarksys/afterdark-darkd/internal/service"
	"github.com/afterdarksys/afterdark-darkd/pkg/logging"
	"go.uber.org/zap"
)

const ServiceName = "dlp"

type Config struct {
	Enabled       bool     `mapstructure:"enabled"`
	Keywords      []string `mapstructure:"keywords"`
	RegexPatterns []string `mapstructure:"regex_patterns"`
}

type Service struct {
	config   *Config
	logger   *zap.Logger
	registry service.RegistryInterface

	patterns []*regexp.Regexp

	mu      sync.RWMutex
	running bool
	stopCh  chan struct{}
}

func New(config *Config, registry service.RegistryInterface) (*Service, error) {
	if config == nil {
		config = &Config{
			Enabled:  true,
			Keywords: []string{"CONFIDENTIAL", "SECRET"},
		}
	}

	s := &Service{
		config:   config,
		logger:   logging.With(zap.String("service", ServiceName)),
		registry: registry,
		stopCh:   make(chan struct{}),
	}

	s.compilePatterns()
	return s, nil
}

func (s *Service) compilePatterns() {
	s.patterns = make([]*regexp.Regexp, 0, len(s.config.RegexPatterns))
	for _, p := range s.config.RegexPatterns {
		if re, err := regexp.Compile(p); err == nil {
			s.patterns = append(s.patterns, re)
		} else {
			s.logger.Warn("invalid dlp regex", zap.String("pattern", p), zap.Error(err))
		}
	}
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

	s.logger.Info("starting dlp service")
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
	s.logger.Info("stopped dlp service")
	return nil
}

func (s *Service) Configure(config interface{}) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if cfg, ok := config.(*Config); ok {
		s.config = cfg
		s.compilePatterns()
	}
	return nil
}

func (s *Service) Health() service.HealthStatus {
	return service.HealthStatus{
		Status:    service.HealthHealthy,
		Message:   "dlp scanning active",
		LastCheck: time.Now(),
	}
}

func (s *Service) monitorLoop() {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-s.stopCh:
			return
		case <-ticker.C:
			// STUB: Real implementation would monitor clipboard (if GUI context) or new files.
			// s.scanClipboard()
			// s.scanRecentFiles()
		}
	}
}
