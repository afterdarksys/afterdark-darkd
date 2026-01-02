package baseline

import (
	"context"
	"sync"
	"time"

	"github.com/afterdarksys/afterdark-darkd/internal/models"
	"github.com/afterdarksys/afterdark-darkd/internal/platform"
	"github.com/afterdarksys/afterdark-darkd/internal/service"
	"github.com/afterdarksys/afterdark-darkd/internal/storage"
	"github.com/afterdarksys/afterdark-darkd/pkg/logging"
	"go.uber.org/zap"
)

const ServiceName = "baseline_scanner"

// Service implements the baseline scanning service
type Service struct {
	config   *models.BaselineScannerConfig
	platform platform.Platform
	store    storage.Store
	logger   *zap.Logger

	mu           sync.RWMutex
	lastScan     time.Time
	applications []platform.Application
	appCount     int

	// Control channels
	stopCh chan struct{}
	doneCh chan struct{}
	scanCh chan struct{}
}

// New creates a new baseline scanner service
func New(cfg *models.BaselineScannerConfig, plat platform.Platform, store storage.Store) *Service {
	return &Service{
		config:   cfg,
		platform: plat,
		store:    store,
		logger:   logging.With(zap.String("service", ServiceName)),
		stopCh:   make(chan struct{}),
		doneCh:   make(chan struct{}),
		scanCh:   make(chan struct{}, 1),
	}
}

// Name returns the service name
func (s *Service) Name() string {
	return ServiceName
}

// Start starts the baseline scanner service
func (s *Service) Start(ctx context.Context) error {
	s.logger.Info("starting baseline scanner service")

	go s.run(ctx)

	// Trigger initial scan
	s.TriggerScan()

	return nil
}

// Stop stops the baseline scanner service
func (s *Service) Stop(ctx context.Context) error {
	s.logger.Info("stopping baseline scanner service")
	close(s.stopCh)

	select {
	case <-s.doneCh:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Health returns the health status
func (s *Service) Health() service.HealthStatus {
	s.mu.RLock()
	defer s.mu.RUnlock()

	status := service.HealthHealthy
	message := "healthy"

	if time.Since(s.lastScan) > s.config.ScanInterval*2 {
		status = service.HealthDegraded
		message = "scan overdue"
	}

	return service.HealthStatus{
		Status:    status,
		Message:   message,
		LastCheck: time.Now(),
		Metrics: map[string]interface{}{
			"last_scan":  s.lastScan,
			"app_count":  s.appCount,
		},
	}
}

// Configure updates the service configuration
func (s *Service) Configure(config interface{}) error {
	if cfg, ok := config.(*models.BaselineScannerConfig); ok {
		s.mu.Lock()
		s.config = cfg
		s.mu.Unlock()
	}
	return nil
}

// TriggerScan triggers an immediate baseline scan
func (s *Service) TriggerScan() {
	select {
	case s.scanCh <- struct{}{}:
	default:
	}
}

// GetApplications returns the list of installed applications
func (s *Service) GetApplications() []platform.Application {
	s.mu.RLock()
	defer s.mu.RUnlock()
	apps := make([]platform.Application, len(s.applications))
	copy(apps, s.applications)
	return apps
}

func (s *Service) run(ctx context.Context) {
	defer close(s.doneCh)

	ticker := time.NewTicker(s.config.ScanInterval)
	defer ticker.Stop()

	for {
		select {
		case <-s.stopCh:
			return
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.performScan(ctx)
		case <-s.scanCh:
			s.performScan(ctx)
		}
	}
}

func (s *Service) performScan(ctx context.Context) {
	s.logger.Info("starting baseline scan")
	startTime := time.Now()

	// Get installed applications
	apps, err := s.platform.ListInstalledApplications(ctx)
	if err != nil {
		s.logger.Error("failed to list applications", zap.Error(err))
		return
	}

	// Update state
	s.mu.Lock()
	s.lastScan = time.Now()
	s.applications = apps
	s.appCount = len(apps)
	s.mu.Unlock()

	// Save to storage
	scanResult := map[string]interface{}{
		"timestamp":   startTime,
		"duration_ms": time.Since(startTime).Milliseconds(),
		"app_count":   len(apps),
		"applications": apps,
	}

	if err := s.store.Save(ctx, "baseline", startTime.Format("20060102-150405"), scanResult); err != nil {
		s.logger.Error("failed to save baseline scan", zap.Error(err))
	}

	s.logger.Info("baseline scan complete",
		zap.Int("applications", len(apps)),
		zap.Duration("duration", time.Since(startTime)),
	)
}
