package persistence

import (
	"context"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/afterdarksys/afterdark-darkd/internal/models"
	"github.com/afterdarksys/afterdark-darkd/internal/service"
	"github.com/afterdarksys/afterdark-darkd/pkg/logging"
	"go.uber.org/zap"
)

type Service struct {
	config     *models.PersistenceConfig
	running    bool
	cancel     context.CancelFunc
	mu         sync.RWMutex
	logger     *zap.Logger
	knownItems map[string]bool // Simplified tracking set
}

func New(cfg *models.PersistenceConfig) *Service {
	if cfg.Interval == 0 {
		cfg.Interval = 10 * time.Minute
	}
	return &Service{
		config:     cfg,
		knownItems: make(map[string]bool),
		logger:     logging.Get().Named("persistence"),
	}
}

func (s *Service) Name() string {
	return "persistence_monitor"
}

func (s *Service) Start(ctx context.Context) error {
	s.mu.Lock()
	if s.running {
		s.mu.Unlock()
		return nil
	}
	s.running = true
	ctx, s.cancel = context.WithCancel(ctx)
	s.mu.Unlock()

	s.logger.Info("starting persistence monitor")
	go s.runLoop(ctx)
	return nil
}

func (s *Service) Stop(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.running {
		return nil
	}
	s.running = false
	if s.cancel != nil {
		s.cancel()
	}
	return nil
}

func (s *Service) Health() service.HealthStatus {
	return service.HealthStatus{
		Status:    service.HealthHealthy,
		Message:   "persistence monitor active",
		LastCheck: time.Now(),
	}
}

func (s *Service) Configure(cfg interface{}) error { return nil }

func (s *Service) runLoop(ctx context.Context) {
	ticker := time.NewTicker(s.config.Interval)
	defer ticker.Stop()

	// Initial Scan
	s.scanPersistence(ctx)

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.scanPersistence(ctx)
		}
	}
}

func (s *Service) scanPersistence(ctx context.Context) {
	s.scanLaunchAgents()
	s.scanCron()
	// Browser extensions scanning logic would go here
}

func (s *Service) scanLaunchAgents() {
	dirs := []string{
		"/Library/LaunchAgents",
		"/Library/LaunchDaemons",
		"/System/Library/LaunchAgents",
		"/System/Library/LaunchDaemons",
	}

	// Add user specific agents if running as root or user
	home, err := os.UserHomeDir()
	if err == nil {
		dirs = append(dirs, filepath.Join(home, "Library/LaunchAgents"))
	}

	for _, dir := range dirs {
		files, err := os.ReadDir(dir)
		if err != nil {
			continue
		}

		for _, f := range files {
			if f.IsDir() {
				continue
			}
			path := filepath.Join(dir, f.Name())
			s.mu.Lock()
			if !s.knownItems[path] {
				s.knownItems[path] = true
				s.logger.Info("found persistence item", zap.String("type", "launch_agent"), zap.String("path", path))
				// Alert logic would go here (new item found)
			}
			s.mu.Unlock()
		}
	}
}

func (s *Service) scanCron() {
	// Scan /etc/crontab and /var/at/tabs (macos) or /var/spool/cron (linux)
	cronDirs := []string{"/var/at/tabs", "/usr/lib/cron/tabs"}
	for _, dir := range cronDirs {
		files, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, f := range files {
			path := filepath.Join(dir, f.Name())
			s.mu.Lock()
			if !s.knownItems[path] {
				s.knownItems[path] = true
				s.logger.Info("found persistence item", zap.String("type", "cron_job"), zap.String("user", f.Name()))
			}
			s.mu.Unlock()
		}
	}
}
