// Package behavior provides behavioral analysis service for the afterdark-darkd daemon.
package behavior

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/afterdarksys/afterdark-darkd/internal/behavior"
	"github.com/afterdarksys/afterdark-darkd/internal/models"
	"go.uber.org/zap"
)

// Service manages behavioral analysis and vulnerability profiling
type Service struct {
	collector       *behavior.Collector
	config          *models.Config
	log             *zap.Logger
	mu              sync.RWMutex
	running         bool
	ctx             context.Context
	cancel          context.CancelFunc
	snapshotInterval time.Duration
	lastSnapshot    time.Time
	lastRiskCheck   time.Time
	currentRiskScore float64
	isVulnerable    bool
}

// Config holds configuration for the behavior service
type Config struct {
	Enabled          bool          `yaml:"enabled" json:"enabled"`
	SnapshotInterval time.Duration `yaml:"snapshot_interval" json:"snapshot_interval"`
	RiskCheckInterval time.Duration `yaml:"risk_check_interval" json:"risk_check_interval"`
	RiskThreshold    float64       `yaml:"risk_threshold" json:"risk_threshold"`
	AlertOnVulnerable bool         `yaml:"alert_on_vulnerable" json:"alert_on_vulnerable"`
}

// DefaultConfig returns default configuration
func DefaultConfig() Config {
	return Config{
		Enabled:          true,
		SnapshotInterval: 6 * time.Hour,
		RiskCheckInterval: 1 * time.Hour,
		RiskThreshold:    7.0,
		AlertOnVulnerable: true,
	}
}

// NewService creates a new behavior analysis service
func NewService(cfg *models.Config, endpointID string, log *zap.Logger) (*Service, error) {
	collector := behavior.NewCollector(cfg, endpointID)

	ctx, cancel := context.WithCancel(context.Background())

	return &Service{
		collector:       collector,
		config:          cfg,
		log:             log.Named("behavior"),
		ctx:             ctx,
		cancel:          cancel,
		snapshotInterval: 6 * time.Hour, // Default
		currentRiskScore: 0.0,
		isVulnerable:    false,
	}, nil
}

// Start starts the behavior analysis service
func (s *Service) Start() error {
	s.mu.Lock()
	if s.running {
		s.mu.Unlock()
		return fmt.Errorf("behavior service already running")
	}
	s.running = true
	s.mu.Unlock()

	s.log.Info("Starting behavior analysis service")

	// Start snapshot collection goroutine
	go s.snapshotLoop()

	// Start risk monitoring goroutine
	go s.riskMonitorLoop()

	// Collect initial snapshot
	go func() {
		if err := s.collectAndSubmitSnapshot(); err != nil {
			s.log.Error("Failed to collect initial snapshot", zap.Error(err))
		}
	}()

	return nil
}

// Stop stops the behavior analysis service
func (s *Service) Stop() error {
	s.mu.Lock()
	if !s.running {
		s.mu.Unlock()
		return nil
	}
	s.running = false
	s.mu.Unlock()

	s.log.Info("Stopping behavior analysis service")
	s.cancel()

	return nil
}

// snapshotLoop periodically collects and submits system snapshots
func (s *Service) snapshotLoop() {
	ticker := time.NewTicker(s.snapshotInterval)
	defer ticker.Stop()

	for {
		select {
		case <-s.ctx.Done():
			return
		case <-ticker.C:
			if err := s.collectAndSubmitSnapshot(); err != nil {
				s.log.Error("Failed to collect and submit snapshot", zap.Error(err))
			}
		}
	}
}

// riskMonitorLoop periodically checks risk score and alerts if vulnerable
func (s *Service) riskMonitorLoop() {
	ticker := time.NewTicker(1 * time.Hour) // Check every hour
	defer ticker.Stop()

	for {
		select {
		case <-s.ctx.Done():
			return
		case <-ticker.C:
			if err := s.checkRiskScore(); err != nil {
				s.log.Warn("Failed to check risk score", zap.Error(err))
			}
		}
	}
}

// collectAndSubmitSnapshot collects current system state and submits to server
func (s *Service) collectAndSubmitSnapshot() error {
	s.log.Info("Collecting system snapshot")

	snapshot, err := s.collector.CollectSnapshot()
	if err != nil {
		return fmt.Errorf("failed to collect snapshot: %w", err)
	}

	s.log.Debug("Snapshot collected",
		zap.Int("processes", len(snapshot.RunningProcesses)),
		zap.Int("connections", len(snapshot.NetworkConnections)),
		zap.Int("packages", len(snapshot.Packages)),
	)

	ctx, cancel := context.WithTimeout(s.ctx, 30*time.Second)
	defer cancel()

	if err := s.collector.SubmitSnapshot(ctx, snapshot); err != nil {
		return fmt.Errorf("failed to submit snapshot: %w", err)
	}

	s.mu.Lock()
	s.lastSnapshot = time.Now()
	s.mu.Unlock()

	s.log.Info("Snapshot submitted successfully")

	// After submitting snapshot, check risk score
	go func() {
		time.Sleep(5 * time.Second) // Give server time to process
		if err := s.checkRiskScore(); err != nil {
			s.log.Warn("Failed to check risk score after snapshot", zap.Error(err))
		}
	}()

	return nil
}

// checkRiskScore retrieves current risk score from server
func (s *Service) checkRiskScore() error {
	ctx, cancel := context.WithTimeout(s.ctx, 10*time.Second)
	defer cancel()

	riskScore, err := s.collector.GetRiskScore(ctx)
	if err != nil {
		return fmt.Errorf("failed to get risk score: %w", err)
	}

	s.mu.Lock()
	previousScore := s.currentRiskScore
	previousVulnerable := s.isVulnerable
	s.currentRiskScore = riskScore.RiskScore
	s.isVulnerable = riskScore.RiskScore >= 7.0 || riskScore.CriticalCount > 0 || riskScore.ExploitAvailable
	s.lastRiskCheck = time.Now()
	s.mu.Unlock()

	s.log.Info("Risk score updated",
		zap.Float64("risk_score", riskScore.RiskScore),
		zap.Int("vulnerabilities", riskScore.VulnerabilityCount),
		zap.Int("critical", riskScore.CriticalCount),
		zap.Int("high", riskScore.HighCount),
		zap.Int("medium", riskScore.MediumCount),
		zap.Int("low", riskScore.LowCount),
		zap.Bool("exploit_avail", riskScore.ExploitAvailable),
	)

	// Alert if newly vulnerable
	if s.isVulnerable && !previousVulnerable {
		s.alertVulnerable(riskScore)
	}

	// Alert if risk score significantly increased
	if riskScore.RiskScore > previousScore+2.0 {
		s.log.Warn("Risk score significantly increased",
			zap.Float64("previous_score", previousScore),
			zap.Float64("current_score", riskScore.RiskScore),
		)
	}

	return nil
}

// alertVulnerable generates an alert when the endpoint is flagged as vulnerable
func (s *Service) alertVulnerable(riskScore *behavior.RiskScoreResponse) {
	s.log.Error("VULNERABLE ENDPOINT DETECTED",
		zap.Float64("risk_score", riskScore.RiskScore),
		zap.Int("vulnerabilities", riskScore.VulnerabilityCount),
		zap.Int("critical_vulns", riskScore.CriticalCount),
		zap.Int("high_vulns", riskScore.HighCount),
		zap.Bool("exploit_available", riskScore.ExploitAvailable),
	)

	// In a production system, this would:
	// 1. Send notification to security team
	// 2. Create incident ticket
	// 3. Trigger automated response (e.g., network isolation)
	// 4. Log to SIEM
	// 5. Display alert to user

	if riskScore.CriticalCount > 0 {
		s.log.Error("CRITICAL: System has critical vulnerabilities",
			zap.Int("critical_count", riskScore.CriticalCount))
	}

	if riskScore.ExploitAvailable {
		s.log.Error("CRITICAL: Public exploits are available for detected vulnerabilities")
	}
}

// GetStatus returns the current status of the behavior service
func (s *Service) GetStatus() map[string]interface{} {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return map[string]interface{}{
		"running":          s.running,
		"last_snapshot":    s.lastSnapshot,
		"last_risk_check":  s.lastRiskCheck,
		"current_risk_score": s.currentRiskScore,
		"is_vulnerable":    s.isVulnerable,
		"snapshot_interval": s.snapshotInterval.String(),
	}
}

// IsVulnerable returns whether the endpoint is currently flagged as vulnerable
func (s *Service) IsVulnerable() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.isVulnerable
}

// GetRiskScore returns the current risk score
func (s *Service) GetRiskScore() float64 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.currentRiskScore
}

// ForceSnapshot forces an immediate snapshot collection
func (s *Service) ForceSnapshot() error {
	return s.collectAndSubmitSnapshot()
}

// ForceRiskCheck forces an immediate risk score check
func (s *Service) ForceRiskCheck() error {
	return s.checkRiskScore()
}
