package canary

import (
	"context"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/afterdarksys/afterdark-darkd/internal/service"
	"github.com/afterdarksys/afterdark-darkd/pkg/logging"
	"github.com/fsnotify/fsnotify"
	"go.uber.org/zap"
)

const ServiceName = "canary"

type Config struct {
	Enabled        bool     `mapstructure:"enabled"`
	DecoyPaths     []string `mapstructure:"decoy_paths"`     // Directories to place decoys
	DecoyFilenames []string `mapstructure:"decoy_filenames"` // Names of decoy files
}

type Service struct {
	config   *Config
	logger   *zap.Logger
	registry service.RegistryInterface
	watcher  *fsnotify.Watcher

	mu      sync.RWMutex
	running bool
	stopCh  chan struct{}
}

func New(config *Config, registry service.RegistryInterface) (*Service, error) {
	if config == nil {
		config = &Config{
			Enabled:        true,
			DecoyPaths:     []string{"/tmp", "/var/tmp"}, // Defaults, should use user home in prod
			DecoyFilenames: []string{".canary.docx", "passwords.txt", "financial_report.xlsx"},
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

	var err error
	s.watcher, err = fsnotify.NewWatcher()
	if err != nil {
		s.mu.Unlock()
		return err
	}

	s.running = true
	s.mu.Unlock()

	s.logger.Info("starting canary service")

	if err := s.deployDecoys(); err != nil {
		s.logger.Error("failed to deploy decoys", zap.Error(err))
	}

	go s.watchLoop()

	return nil
}

func (s *Service) Stop(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.running {
		return nil
	}
	s.running = false
	if s.watcher != nil {
		s.watcher.Close()
	}
	close(s.stopCh)
	s.logger.Info("stopped canary service")
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
		Message:   "canaries deployed",
		LastCheck: time.Now(),
	}
}

func (s *Service) deployDecoys() error {
	for _, dir := range s.config.DecoyPaths {
		for _, name := range s.config.DecoyFilenames {
			path := filepath.Join(dir, name)

			// Check if exists
			if _, err := os.Stat(path); err == nil {
				// Already exists, just watch it
				if err := s.watcher.Add(path); err != nil {
					s.logger.Warn("failed to watch existing decoy", zap.String("path", path), zap.Error(err))
				}
				continue
			}

			// Create dummy file
			err := os.WriteFile(path, []byte("Confidential Data - Do Not Read"), 0644)
			if err != nil {
				s.logger.Warn("failed to create decoy", zap.String("path", path), zap.Error(err))
				continue
			}

			// Watch it
			if err := s.watcher.Add(path); err != nil {
				s.logger.Warn("failed to watch new decoy", zap.String("path", path), zap.Error(err))
			}
			s.logger.Info("deployed decoy", zap.String("path", path))
		}
	}
	return nil
}

func (s *Service) watchLoop() {
	for {
		select {
		case event, ok := <-s.watcher.Events:
			if !ok {
				return
			}
			if event.Op&fsnotify.Write == fsnotify.Write || event.Op&fsnotify.Remove == fsnotify.Remove {
				s.logger.Warn("RANSOMWARE ALERT: Canary file modified!", zap.String("file", event.Name), zap.String("op", event.Op.String()))
				// Trigger alert mechanism here
			}
		case err, ok := <-s.watcher.Errors:
			if !ok {
				return
			}
			s.logger.Error("watcher error", zap.Error(err))
		case <-s.stopCh:
			return
		}
	}
}
