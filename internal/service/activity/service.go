package activity

import (
	"context"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/afterdarksys/afterdark-darkd/internal/models"
	"github.com/afterdarksys/afterdark-darkd/internal/service"
	"github.com/afterdarksys/afterdark-darkd/pkg/logging"
	"go.uber.org/zap"
)

type Service struct {
	config  *models.ActivityConfig
	running bool
	cancel  context.CancelFunc
	mu      sync.RWMutex
	logger  *zap.Logger
}

func New(cfg *models.ActivityConfig) *Service {
	if cfg.Interval == 0 {
		cfg.Interval = 1 * time.Minute
	}
	return &Service{
		config: cfg,
		logger: logging.Get().Named("activity"),
	}
}

func (s *Service) Name() string {
	return "activity_monitor"
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

	s.logger.Info("starting activity monitor")
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
		Message:   "activity monitor active",
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
			s.checkShadowIT()
			// Log watching would happen in a separate goroutine usually
		}
	}
}

func (s *Service) checkShadowIT() {
	// Check for interfaces in promiscuous mode (Shadow IT detection)
	ifaces, err := net.Interfaces()
	if err != nil {
		s.logger.Error("failed to list interfaces", zap.Error(err))
		return
	}

	for _, iface := range ifaces {
		// This is a heuristic: "P" is often used in flag strings for promiscuous,
		// but Go's Interface.Flags doesn't expose Promiscuous directly in the standard String() always platform-independently.
		// However, standard flags usually show "up|broadcast|multicast".
		// Promiscuous mode detection often requires platform specific syscalls.
		// For this implementation, we will log any interface that has "suspiciously" high flags or check specific states if we could.

		// As a placeholder for the "Shadow IT" feature requested:
		if strings.Contains(iface.Flags.String(), "promisc") {
			// Note: Go's net package String() method might not print "promisc" on all platforms even if set.
			s.logger.Warn("network interface in promiscuous mode detected",
				zap.String("interface", iface.Name))
		}
	}
}
