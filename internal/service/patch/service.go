package patch

import (
	"context"
	"sync"
	"time"

	"github.com/afterdarksys/afterdark-darkd/internal/api/afterdark"
	"github.com/afterdarksys/afterdark-darkd/internal/models"
	"github.com/afterdarksys/afterdark-darkd/internal/platform"
	"github.com/afterdarksys/afterdark-darkd/internal/service"
	"github.com/afterdarksys/afterdark-darkd/internal/storage"
	"github.com/afterdarksys/afterdark-darkd/pkg/logging"
	"go.uber.org/zap"
)

const ServiceName = "patch_monitor"

// Service implements the patch monitoring service
type Service struct {
	config     *models.PatchMonitorConfig
	platform   platform.Platform
	store      storage.Store
	apiClient  *afterdark.Client
	logger     *zap.Logger

	mu            sync.RWMutex
	lastScan      time.Time
	compliance    *ComplianceStatus
	missingPatches []platform.Patch

	// Control channels
	stopCh   chan struct{}
	doneCh   chan struct{}
	scanCh   chan struct{}
}

// ComplianceStatus represents the current compliance state
type ComplianceStatus struct {
	Compliant       bool      `json:"compliant"`
	LastScan        time.Time `json:"last_scan"`
	NextScan        time.Time `json:"next_scan"`
	CriticalMissing int       `json:"critical_missing"`
	ImportantMissing int      `json:"important_missing"`
	TotalMissing    int       `json:"total_missing"`
	UrgentActions   []UrgentAction `json:"urgent_actions,omitempty"`
}

// UrgentAction represents an urgent patch action needed
type UrgentAction struct {
	Patch       platform.Patch `json:"patch"`
	DueBy       time.Time      `json:"due_by"`
	UrgencyDays int            `json:"urgency_days"`
	Reason      string         `json:"reason"`
}

// New creates a new patch monitor service
func New(cfg *models.PatchMonitorConfig, plat platform.Platform, store storage.Store, apiClient *afterdark.Client) *Service {
	return &Service{
		config:    cfg,
		platform:  plat,
		store:     store,
		apiClient: apiClient,
		logger:    logging.With(zap.String("service", ServiceName)),
		stopCh:    make(chan struct{}),
		doneCh:    make(chan struct{}),
		scanCh:    make(chan struct{}, 1),
		compliance: &ComplianceStatus{},
	}
}

// Name returns the service name
func (s *Service) Name() string {
	return ServiceName
}

// Start starts the patch monitor service
func (s *Service) Start(ctx context.Context) error {
	s.logger.Info("starting patch monitor service")

	go s.run(ctx)

	// Trigger initial scan
	s.TriggerScan()

	return nil
}

// Stop stops the patch monitor service
func (s *Service) Stop(ctx context.Context) error {
	s.logger.Info("stopping patch monitor service")
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
			"last_scan":       s.lastScan,
			"missing_patches": len(s.missingPatches),
			"compliant":       s.compliance.Compliant,
		},
	}
}

// Configure updates the service configuration
func (s *Service) Configure(config interface{}) error {
	if cfg, ok := config.(*models.PatchMonitorConfig); ok {
		s.mu.Lock()
		s.config = cfg
		s.mu.Unlock()
	}
	return nil
}

// TriggerScan triggers an immediate patch scan
func (s *Service) TriggerScan() {
	select {
	case s.scanCh <- struct{}{}:
	default:
		// Scan already pending
	}
}

// GetComplianceStatus returns the current compliance status
func (s *Service) GetComplianceStatus() *ComplianceStatus {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.compliance
}

// GetMissingPatches returns the list of missing patches
func (s *Service) GetMissingPatches() []platform.Patch {
	s.mu.RLock()
	defer s.mu.RUnlock()
	patches := make([]platform.Patch, len(s.missingPatches))
	copy(patches, s.missingPatches)
	return patches
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
	s.logger.Info("starting patch scan")
	startTime := time.Now()

	// Get available patches from platform
	available, err := s.platform.ListAvailablePatches(ctx)
	if err != nil {
		s.logger.Error("failed to list available patches", zap.Error(err))
		return
	}

	// Get installed patches
	installed, err := s.platform.ListInstalledPatches(ctx)
	if err != nil {
		s.logger.Error("failed to list installed patches", zap.Error(err))
		return
	}

	// Build installed patch set for quick lookup
	installedSet := make(map[string]bool)
	for _, p := range installed {
		installedSet[p.ID] = true
	}

	// Find missing patches
	var missing []platform.Patch
	for _, p := range available {
		if !installedSet[p.ID] {
			missing = append(missing, p)
		}
	}

	// Classify urgency and build compliance status
	compliance := s.buildComplianceStatus(missing)

	// Update state
	s.mu.Lock()
	s.lastScan = time.Now()
	s.missingPatches = missing
	s.compliance = compliance
	s.mu.Unlock()

	// Save to storage
	scanResult := map[string]interface{}{
		"timestamp":        startTime,
		"duration_ms":      time.Since(startTime).Milliseconds(),
		"installed_count":  len(installed),
		"available_count":  len(available),
		"missing_count":    len(missing),
		"compliance":       compliance,
	}

	if err := s.store.Save(ctx, "scans", startTime.Format("20060102-150405"), scanResult); err != nil {
		s.logger.Error("failed to save scan result", zap.Error(err))
	}

	s.logger.Info("patch scan complete",
		zap.Int("installed", len(installed)),
		zap.Int("available", len(available)),
		zap.Int("missing", len(missing)),
		zap.Bool("compliant", compliance.Compliant),
		zap.Duration("duration", time.Since(startTime)),
	)
}

func (s *Service) buildComplianceStatus(missing []platform.Patch) *ComplianceStatus {
	status := &ComplianceStatus{
		Compliant:    true,
		LastScan:     time.Now(),
		NextScan:     time.Now().Add(s.config.ScanInterval),
		TotalMissing: len(missing),
	}

	now := time.Now()

	for _, p := range missing {
		// Count by severity
		switch p.Severity {
		case platform.SeverityCritical, platform.SeverityExploitActive:
			status.CriticalMissing++
		case platform.SeverityImportant:
			status.ImportantMissing++
		}

		// Determine urgency
		urgency := s.getUrgencyForPatch(p)
		dueBy := p.ReleasedAt.Add(urgency)

		if now.After(dueBy) {
			status.Compliant = false
			status.UrgentActions = append(status.UrgentActions, UrgentAction{
				Patch:       p,
				DueBy:       dueBy,
				UrgencyDays: int(urgency.Hours() / 24),
				Reason:      s.getUrgencyReason(p),
			})
		}
	}

	return status
}

func (s *Service) getUrgencyForPatch(p platform.Patch) time.Duration {
	// Critical or exploit active -> 1 day
	if p.Severity == platform.SeverityCritical || p.Severity == platform.SeverityExploitActive {
		return s.config.UrgencyTiers.Critical
	}

	// Kernel or network -> 2 days
	if p.Category == platform.CategoryKernel || p.Category == platform.CategoryNetwork {
		return s.config.UrgencyTiers.KernelNetwork
	}

	// Software patches -> 3 days
	if p.Category == platform.CategorySoftware {
		return s.config.UrgencyTiers.Software
	}

	// Default to Windows standard (7 days)
	return s.config.UrgencyTiers.WindowsStandard
}

func (s *Service) getUrgencyReason(p platform.Patch) string {
	if p.Severity == platform.SeverityExploitActive {
		return "Active exploit in the wild"
	}
	if p.Severity == platform.SeverityCritical {
		return "Critical severity"
	}
	if p.Category == platform.CategoryKernel {
		return "Kernel patch"
	}
	if p.Category == platform.CategoryNetwork {
		return "Network-related patch"
	}
	return "Software update"
}
