package integrity

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"sync"
	"time"

	"github.com/afterdarksys/afterdark-darkd/internal/models"
	"github.com/afterdarksys/afterdark-darkd/internal/service"
	"github.com/afterdarksys/afterdark-darkd/pkg/logging"
	"go.uber.org/zap"
)

type Service struct {
	config  *models.IntegrityConfig
	running bool
	cancel  context.CancelFunc
	mu      sync.RWMutex
	logger  *zap.Logger
	hashes  map[string]string
}

func New(cfg *models.IntegrityConfig) *Service {
	if cfg.Interval == 0 {
		cfg.Interval = 5 * time.Minute
	}
	// Default watched files if empty
	if len(cfg.WatchedFiles) == 0 {
		cfg.WatchedFiles = []string{
			"/etc/hosts",
			"/etc/passwd",
			"/etc/sudoers",
			"/etc/ssh/sshd_config",
		}
	}

	return &Service{
		config: cfg,
		hashes: make(map[string]string),
		logger: logging.Get().Named("integrity"),
	}
}

func (s *Service) Name() string {
	return "integrity_monitor"
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

	s.logger.Info("starting integrity monitor", zap.Int("files", len(s.config.WatchedFiles)))

	// Initial scan
	s.scanFiles()

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
	s.logger.Info("integrity monitor stopped")
	return nil
}

func (s *Service) Health() service.HealthStatus {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return service.HealthStatus{
		Status:    service.HealthHealthy,
		Message:   "integrity monitor active",
		LastCheck: time.Now(),
		Metrics: map[string]interface{}{
			"watched_files": len(s.config.WatchedFiles),
		},
	}
}

func (s *Service) Configure(cfg interface{}) error {
	return nil // Todo
}

func (s *Service) runLoop(ctx context.Context) {
	ticker := time.NewTicker(s.config.Interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.scanFiles()
		}
	}
}

func (s *Service) scanFiles() {
	for _, path := range s.config.WatchedFiles {
		s.checkFile(path)
	}
}

func (s *Service) checkFile(path string) {
	hash, err := hashFile(path)
	if err != nil {
		if !os.IsNotExist(err) {
			s.logger.Warn("failed to hash file", zap.String("path", path), zap.Error(err))
		}
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	oldHash, exists := s.hashes[path]
	if exists && oldHash != hash {
		s.logger.Warn("file integrity violation detected",
			zap.String("path", path),
			zap.String("old_hash", oldHash),
			zap.String("new_hash", hash))
		// Here we would properly dispatch an alert event
	} else if !exists {
		s.logger.Debug("started tracking file", zap.String("path", path))
	}

	s.hashes[path] = hash
}

func hashFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}

	return hex.EncodeToString(h.Sum(nil)), nil
}
