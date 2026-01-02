package network

import (
	"context"
	"sync"
	"time"

	"github.com/afterdarksys/afterdark-darkd/internal/models"
	"github.com/afterdarksys/afterdark-darkd/internal/platform"
	"github.com/afterdarksys/afterdark-darkd/internal/service"
	"github.com/afterdarksys/afterdark-darkd/pkg/logging"
	"go.uber.org/zap"
)

const ServiceName = "network_monitor"

// Service implements the network monitoring service
type Service struct {
	config   *models.NetworkMonitorConfig
	platform platform.Platform
	logger   *zap.Logger

	mu          sync.RWMutex
	dnsConfigured bool
	icmpBlocked   bool
	fragBlocked   bool
	publicIP      string
	lastCheck     time.Time

	// Control channels
	stopCh chan struct{}
	doneCh chan struct{}
}

// New creates a new network monitor service
func New(cfg *models.NetworkMonitorConfig, plat platform.Platform) *Service {
	return &Service{
		config:   cfg,
		platform: plat,
		logger:   logging.With(zap.String("service", ServiceName)),
		stopCh:   make(chan struct{}),
		doneCh:   make(chan struct{}),
	}
}

// Name returns the service name
func (s *Service) Name() string {
	return ServiceName
}

// Start starts the network monitor service
func (s *Service) Start(ctx context.Context) error {
	s.logger.Info("starting network monitor service")

	// Apply initial configuration
	if err := s.applyConfig(ctx); err != nil {
		s.logger.Error("failed to apply network config", zap.Error(err))
	}

	go s.run(ctx)

	return nil
}

// Stop stops the network monitor service
func (s *Service) Stop(ctx context.Context) error {
	s.logger.Info("stopping network monitor service")
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

	if !s.dnsConfigured && len(s.config.DNSServers) > 0 {
		status = service.HealthDegraded
		message = "DNS not configured"
	}

	return service.HealthStatus{
		Status:    status,
		Message:   message,
		LastCheck: time.Now(),
		Metrics: map[string]interface{}{
			"dns_configured": s.dnsConfigured,
			"icmp_blocked":   s.icmpBlocked,
			"frag_blocked":   s.fragBlocked,
			"public_ip":      s.publicIP,
		},
	}
}

// Configure updates the service configuration
func (s *Service) Configure(config interface{}) error {
	if cfg, ok := config.(*models.NetworkMonitorConfig); ok {
		s.mu.Lock()
		s.config = cfg
		s.mu.Unlock()
		return s.applyConfig(context.Background())
	}
	return nil
}

// GetPublicIP returns the current public IP
func (s *Service) GetPublicIP() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.publicIP
}

// Status returns the network status
type Status struct {
	DNSConfigured bool     `json:"dns_configured"`
	DNSServers    []string `json:"dns_servers"`
	ICMPBlocked   bool     `json:"icmp_blocked"`
	FragBlocked   bool     `json:"frag_blocked"`
	PublicIP      string   `json:"public_ip,omitempty"`
	LastCheck     time.Time `json:"last_check"`
}

func (s *Service) Status() *Status {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return &Status{
		DNSConfigured: s.dnsConfigured,
		DNSServers:    s.config.DNSServers,
		ICMPBlocked:   s.icmpBlocked,
		FragBlocked:   s.fragBlocked,
		PublicIP:      s.publicIP,
		LastCheck:     s.lastCheck,
	}
}

func (s *Service) run(ctx context.Context) {
	defer close(s.doneCh)

	// Check every 5 minutes
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-s.stopCh:
			return
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.checkStatus(ctx)
		}
	}
}

func (s *Service) applyConfig(ctx context.Context) error {
	s.logger.Info("applying network configuration")

	// Configure DNS servers
	if len(s.config.DNSServers) > 0 {
		if err := s.platform.SetDNSServers(s.config.DNSServers); err != nil {
			s.logger.Error("failed to set DNS servers", zap.Error(err))
		} else {
			s.mu.Lock()
			s.dnsConfigured = true
			s.mu.Unlock()
			s.logger.Info("DNS servers configured", zap.Strings("servers", s.config.DNSServers))
		}
	}

	// Configure ICMP
	if !s.config.AllowICMP {
		if err := s.platform.DisableICMP(true); err != nil {
			s.logger.Error("failed to disable ICMP", zap.Error(err))
		} else {
			s.mu.Lock()
			s.icmpBlocked = true
			s.mu.Unlock()
			s.logger.Info("ICMP disabled")
		}
	}

	// Configure IP fragmentation
	if s.config.BlockFragmentation {
		if err := s.platform.BlockIPFragmentation(true); err != nil {
			s.logger.Error("failed to block IP fragmentation", zap.Error(err))
		} else {
			s.mu.Lock()
			s.fragBlocked = true
			s.mu.Unlock()
			s.logger.Info("IP fragmentation blocked")
		}
	}

	return nil
}

func (s *Service) checkStatus(ctx context.Context) {
	s.logger.Debug("checking network status")

	// Get public IP
	ip, err := s.platform.GetPublicIP(ctx)
	if err != nil {
		s.logger.Debug("failed to get public IP", zap.Error(err))
	}

	s.mu.Lock()
	s.publicIP = ip
	s.lastCheck = time.Now()
	s.mu.Unlock()
}
