package threat

import (
	"context"
	"strings"
	"sync"
	"time"

	"github.com/afterdarksys/afterdark-darkd/internal/api/darkapi"
	"github.com/afterdarksys/afterdark-darkd/internal/models"
	"github.com/afterdarksys/afterdark-darkd/internal/service"
	"github.com/afterdarksys/afterdark-darkd/internal/storage"
	"github.com/afterdarksys/afterdark-darkd/pkg/logging"
	"go.uber.org/zap"
)

const ServiceName = "threat_intel"

// Service implements the threat intelligence service
type Service struct {
	config    *models.ThreatIntelConfig
	store     storage.Store
	apiClient *darkapi.Client
	logger    *zap.Logger

	mu          sync.RWMutex
	lastSync    time.Time
	badDomains  map[string]*darkapi.ThreatInfo
	badIPs      map[string]*darkapi.ThreatInfo
	domainCount int
	ipCount     int

	// Control channels
	stopCh chan struct{}
	doneCh chan struct{}
	syncCh chan struct{}
}

// New creates a new threat intel service
func New(cfg *models.ThreatIntelConfig, store storage.Store, apiClient *darkapi.Client) *Service {
	return &Service{
		config:     cfg,
		store:      store,
		apiClient:  apiClient,
		logger:     logging.With(zap.String("service", ServiceName)),
		badDomains: make(map[string]*darkapi.ThreatInfo),
		badIPs:     make(map[string]*darkapi.ThreatInfo),
		stopCh:     make(chan struct{}),
		doneCh:     make(chan struct{}),
		syncCh:     make(chan struct{}, 1),
	}
}

// Name returns the service name
func (s *Service) Name() string {
	return ServiceName
}

// Start starts the threat intel service
func (s *Service) Start(ctx context.Context) error {
	s.logger.Info("starting threat intel service")

	// Load cached data from storage
	if err := s.loadCache(ctx); err != nil {
		s.logger.Warn("failed to load cached threat data", zap.Error(err))
	}

	go s.run(ctx)

	// Trigger initial sync
	s.TriggerSync()

	return nil
}

// Stop stops the threat intel service
func (s *Service) Stop(ctx context.Context) error {
	s.logger.Info("stopping threat intel service")
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

	if time.Since(s.lastSync) > s.config.SyncInterval*2 {
		status = service.HealthDegraded
		message = "sync overdue"
	}

	if s.domainCount == 0 && s.ipCount == 0 {
		status = service.HealthDegraded
		message = "no threat data loaded"
	}

	return service.HealthStatus{
		Status:    status,
		Message:   message,
		LastCheck: time.Now(),
		Metrics: map[string]interface{}{
			"last_sync":    s.lastSync,
			"domain_count": s.domainCount,
			"ip_count":     s.ipCount,
		},
	}
}

// Configure updates the service configuration
func (s *Service) Configure(config interface{}) error {
	if cfg, ok := config.(*models.ThreatIntelConfig); ok {
		s.mu.Lock()
		s.config = cfg
		s.mu.Unlock()
	}
	return nil
}

// TriggerSync triggers an immediate threat intel sync
func (s *Service) TriggerSync() {
	select {
	case s.syncCh <- struct{}{}:
	default:
		// Sync already pending
	}
}

// IsDomainMalicious checks if a domain is in the bad list
func (s *Service) IsDomainMalicious(domain string) (bool, *darkapi.ThreatInfo) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	// Normalize domain
	domain = strings.ToLower(strings.TrimSpace(domain))

	// Direct lookup
	if info, ok := s.badDomains[domain]; ok {
		return true, info
	}

	// Check parent domains (e.g., sub.evil.com -> evil.com)
	parts := strings.Split(domain, ".")
	for i := 1; i < len(parts)-1; i++ {
		parent := strings.Join(parts[i:], ".")
		if info, ok := s.badDomains[parent]; ok {
			return true, info
		}
	}

	return false, nil
}

// IsIPMalicious checks if an IP is in the bad list
func (s *Service) IsIPMalicious(ip string) (bool, *darkapi.ThreatInfo) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	ip = strings.TrimSpace(ip)

	if info, ok := s.badIPs[ip]; ok {
		return true, info
	}

	return false, nil
}

// GetBadDomains returns all bad domains
func (s *Service) GetBadDomains() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()

	domains := make([]string, 0, len(s.badDomains))
	for d := range s.badDomains {
		domains = append(domains, d)
	}
	return domains
}

// GetBadIPs returns all bad IPs
func (s *Service) GetBadIPs() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()

	ips := make([]string, 0, len(s.badIPs))
	for ip := range s.badIPs {
		ips = append(ips, ip)
	}
	return ips
}

// GetLastSync returns the last sync time
func (s *Service) GetLastSync() time.Time {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.lastSync
}

// Stats returns threat intel statistics
type Stats struct {
	LastSync    time.Time `json:"last_sync"`
	DomainCount int       `json:"domain_count"`
	IPCount     int       `json:"ip_count"`
}

func (s *Service) Stats() *Stats {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return &Stats{
		LastSync:    s.lastSync,
		DomainCount: s.domainCount,
		IPCount:     s.ipCount,
	}
}

func (s *Service) run(ctx context.Context) {
	defer close(s.doneCh)

	ticker := time.NewTicker(s.config.SyncInterval)
	defer ticker.Stop()

	for {
		select {
		case <-s.stopCh:
			return
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.performSync(ctx)
		case <-s.syncCh:
			s.performSync(ctx)
		}
	}
}

func (s *Service) performSync(ctx context.Context) {
	s.logger.Info("starting threat intel sync")
	startTime := time.Now()

	// Get bad domains
	domainList, err := s.apiClient.GetBadDomains(ctx)
	if err != nil {
		s.logger.Error("failed to fetch bad domains", zap.Error(err))
	}

	// Get bad IPs
	ipList, err := s.apiClient.GetBadIPs(ctx)
	if err != nil {
		s.logger.Error("failed to fetch bad IPs", zap.Error(err))
	}

	// Update in-memory cache
	s.mu.Lock()
	if domainList != nil {
		s.badDomains = make(map[string]*darkapi.ThreatInfo)
		for _, d := range domainList.Domains {
			s.badDomains[strings.ToLower(d)] = &darkapi.ThreatInfo{
				Indicator: d,
				Type:      "domain",
			}
		}
		s.domainCount = len(s.badDomains)
	}

	if ipList != nil {
		s.badIPs = make(map[string]*darkapi.ThreatInfo)
		for _, ip := range ipList.IPs {
			s.badIPs[ip] = &darkapi.ThreatInfo{
				Indicator: ip,
				Type:      "ip",
			}
		}
		s.ipCount = len(s.badIPs)
	}
	s.lastSync = time.Now()
	s.mu.Unlock()

	// Persist to storage
	if err := s.persistCache(ctx); err != nil {
		s.logger.Error("failed to persist threat cache", zap.Error(err))
	}

	s.logger.Info("threat intel sync complete",
		zap.Int("domains", s.domainCount),
		zap.Int("ips", s.ipCount),
		zap.Duration("duration", time.Since(startTime)),
	)
}

func (s *Service) loadCache(ctx context.Context) error {
	var cached struct {
		LastSync time.Time `json:"last_sync"`
		Domains  []string  `json:"domains"`
		IPs      []string  `json:"ips"`
	}

	if err := s.store.Load(ctx, "threat_intel", "cache", &cached); err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	s.lastSync = cached.LastSync
	for _, d := range cached.Domains {
		s.badDomains[strings.ToLower(d)] = &darkapi.ThreatInfo{
			Indicator: d,
			Type:      "domain",
		}
	}
	s.domainCount = len(s.badDomains)

	for _, ip := range cached.IPs {
		s.badIPs[ip] = &darkapi.ThreatInfo{
			Indicator: ip,
			Type:      "ip",
		}
	}
	s.ipCount = len(s.badIPs)

	return nil
}

func (s *Service) persistCache(ctx context.Context) error {
	s.mu.RLock()
	defer s.mu.RUnlock()

	domains := make([]string, 0, len(s.badDomains))
	for d := range s.badDomains {
		domains = append(domains, d)
	}

	ips := make([]string, 0, len(s.badIPs))
	for ip := range s.badIPs {
		ips = append(ips, ip)
	}

	cached := struct {
		LastSync time.Time `json:"last_sync"`
		Domains  []string  `json:"domains"`
		IPs      []string  `json:"ips"`
	}{
		LastSync: s.lastSync,
		Domains:  domains,
		IPs:      ips,
	}

	return s.store.Save(ctx, "threat_intel", "cache", cached)
}
