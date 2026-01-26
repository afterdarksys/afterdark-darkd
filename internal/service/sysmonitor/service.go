package sysmonitor

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/afterdarksys/afterdark-darkd/internal/models"
	"github.com/afterdarksys/afterdark-darkd/internal/service"
	"github.com/afterdarksys/afterdark-darkd/pkg/logging"
	"go.uber.org/zap"
)

type Service struct {
	config         *models.SysMonitorConfig
	running        bool
	cancel         context.CancelFunc
	mu             sync.RWMutex
	logger         *zap.Logger
	mountedVolumes map[string]bool
}

func New(cfg *models.SysMonitorConfig) *Service {
	if cfg.Interval == 0 {
		cfg.Interval = 30 * time.Second
	}
	return &Service{
		config:         cfg,
		mountedVolumes: make(map[string]bool),
		logger:         logging.Get().Named("sysmonitor"),
	}
}

func (s *Service) Name() string {
	return "system_monitor"
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

	s.logger.Info("starting system monitor")

	// Initial population of volumes
	s.checkUSBDevices()

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
		Message:   "system monitor active",
		LastCheck: time.Now(),
	}
}

func (s *Service) Configure(cfg interface{}) error { return nil }

func (s *Service) runLoop(ctx context.Context) {
	ticker := time.NewTicker(s.config.Interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.checkUSBDevices()
			s.checkEnvVars()
		}
	}
}

func (s *Service) checkUSBDevices() {
	// Simple heuristic: Watch /Volumes on macOS
	matches, err := filepath.Glob("/Volumes/*")
	if err != nil {
		return
	}

	current := make(map[string]bool)
	for _, m := range matches {
		// Ignore standard volumes like Macintosh HD
		if strings.Contains(m, "Macintosh HD") || strings.Contains(m, "com.apple") {
			continue
		}
		current[m] = true
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	// Check for new
	for vol := range current {
		if !s.mountedVolumes[vol] {
			s.logger.Info("new external volume detected", zap.String("path", vol))
			// Alert: USB/External drive connected
		}
	}

	s.mountedVolumes = current
}

func (s *Service) checkEnvVars() {
	// Monitor for suspicious environment variables in the current process context
	// In a real agent, we might scan other process environments if possible
	suspicious := []string{"LD_PRELOAD", "DYLD_INSERT_LIBRARIES"}

	for _, env := range suspicious {
		if val := os.Getenv(env); val != "" {
			s.logger.Warn("suspicious environment variable detected",
				zap.String("var", env),
				zap.String("value", val))
		}
	}
}
