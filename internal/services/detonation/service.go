package detonation

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/afterdarksys/afterdark-darkd/internal/api"
	"github.com/afterdarksys/afterdark-darkd/internal/models"
	"github.com/fsnotify/fsnotify"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

// KVStore is a simple key-value store interface for detonation data
type KVStore interface {
	Get(key string) ([]byte, error)
	Set(key string, value []byte) error
	Delete(key string) error
}

// Service provides malware detonation and analysis capabilities
type Service struct {
	config    models.DetonationConfig
	logger    *zap.Logger
	store     KVStore
	apiClient *api.Client
	analyzer  *FileAnalyzer
	sandbox   *Sandbox
	watcher   *fsnotify.Watcher

	// Queue management
	queue     chan *models.DetonationSample
	semaphore chan struct{}

	// Sample tracking
	samples   map[string]*models.DetonationSample
	samplesMu sync.RWMutex

	// Portal upload batch
	uploadQueue   []*models.DetonationReport
	uploadQueueMu sync.Mutex
	lastUpload    time.Time

	// Service lifecycle
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// NewService creates a new detonation service
func NewService(
	cfg models.DetonationConfig,
	logger *zap.Logger,
	store KVStore,
	apiClient *api.Client,
) (*Service, error) {
	ctx, cancel := context.WithCancel(context.Background())

	s := &Service{
		config:    cfg,
		logger:    logger.Named("detonation"),
		store:     store,
		apiClient: apiClient,
		queue:     make(chan *models.DetonationSample, 100),
		semaphore: make(chan struct{}, cfg.MaxConcurrent),
		samples:   make(map[string]*models.DetonationSample),
		ctx:       ctx,
		cancel:    cancel,
	}

	// Initialize file analyzer
	s.analyzer = NewFileAnalyzer(cfg.YaraRulesDir, cfg.EnableYara)

	// Initialize sandbox
	sandbox, err := NewSandbox(SandboxConfig{
		Type:        SandboxType(cfg.SandboxType),
		DockerImage: cfg.DockerImage,
		Timeout:     cfg.DetonationTimeout,
		WorkDir:     cfg.QuarantineDir,
	}, logger)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("failed to initialize sandbox: %w", err)
	}
	s.sandbox = sandbox

	// Initialize file watcher
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		cancel()
		return nil, fmt.Errorf("failed to create watcher: %w", err)
	}
	s.watcher = watcher

	return s, nil
}

// Start begins the detonation service
func (s *Service) Start() error {
	s.logger.Info("starting detonation chamber service",
		zap.String("sandbox_type", s.config.SandboxType),
		zap.Int("max_concurrent", s.config.MaxConcurrent),
	)

	// Ensure watch directories exist
	for _, dir := range s.config.WatchDirs {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("failed to create watch dir %s: %w", dir, err)
		}
		if err := s.watcher.Add(dir); err != nil {
			return fmt.Errorf("failed to watch dir %s: %w", dir, err)
		}
		s.logger.Info("watching directory", zap.String("path", dir))
	}

	// Start workers
	s.wg.Add(3)
	go s.watcherLoop()
	go s.processingLoop()
	go s.uploadLoop()

	// Scan existing files in watch directories
	go s.scanExistingFiles()

	return nil
}

// Stop gracefully shuts down the service
func (s *Service) Stop() error {
	s.logger.Info("stopping detonation chamber service")
	s.cancel()
	s.watcher.Close()
	close(s.queue)
	s.wg.Wait()

	// Final upload of any pending reports
	s.flushUploadQueue()

	return nil
}

// Name returns the service name
func (s *Service) Name() string {
	return "detonation-chamber"
}

// watcherLoop monitors directories for new files
func (s *Service) watcherLoop() {
	defer s.wg.Done()

	for {
		select {
		case <-s.ctx.Done():
			return
		case event, ok := <-s.watcher.Events:
			if !ok {
				return
			}
			if event.Op&fsnotify.Create == fsnotify.Create {
				s.handleNewFile(event.Name)
			}
		case err, ok := <-s.watcher.Errors:
			if !ok {
				return
			}
			s.logger.Error("watcher error", zap.Error(err))
		}
	}
}

// processingLoop handles the detonation queue
func (s *Service) processingLoop() {
	defer s.wg.Done()

	for sample := range s.queue {
		select {
		case <-s.ctx.Done():
			return
		case s.semaphore <- struct{}{}: // Acquire semaphore
			go func(sample *models.DetonationSample) {
				defer func() { <-s.semaphore }() // Release semaphore
				s.processSample(sample)
			}(sample)
		}
	}
}

// uploadLoop periodically uploads reports to the portal
func (s *Service) uploadLoop() {
	defer s.wg.Done()

	ticker := time.NewTicker(s.config.PortalUpload.BatchInterval)
	defer ticker.Stop()

	for {
		select {
		case <-s.ctx.Done():
			return
		case <-ticker.C:
			s.flushUploadQueue()
		}
	}
}

// handleNewFile processes a newly detected file
func (s *Service) handleNewFile(path string) {
	// Check if file type is supported
	ext := strings.ToLower(filepath.Ext(path))
	if !s.isSupportedType(ext) {
		s.logger.Debug("skipping unsupported file type",
			zap.String("path", path),
			zap.String("ext", ext),
		)
		return
	}

	// Check file size
	stat, err := os.Stat(path)
	if err != nil {
		s.logger.Warn("failed to stat file", zap.String("path", path), zap.Error(err))
		return
	}
	if stat.Size() > s.config.MaxFileSize {
		s.logger.Warn("file too large for detonation",
			zap.String("path", path),
			zap.Int64("size", stat.Size()),
			zap.Int64("max_size", s.config.MaxFileSize),
		)
		return
	}

	// Analyze file
	sample, err := s.analyzer.AnalyzeFile(path)
	if err != nil {
		s.logger.Error("failed to analyze file", zap.String("path", path), zap.Error(err))
		return
	}

	// Generate sample ID
	sample.ID = uuid.New().String()
	sample.SubmittedAt = time.Now()

	// Check if we've seen this hash before
	s.updateFrequency(sample)

	// Get location info
	sample.Location = s.getLocationInfo(path)

	// Store sample
	s.samplesMu.Lock()
	s.samples[sample.ID] = sample
	s.samplesMu.Unlock()

	// Queue for processing
	if s.config.AutoSubmit {
		sample.Status = models.DetonationStatusQueued
		select {
		case s.queue <- sample:
			s.logger.Info("queued sample for detonation",
				zap.String("id", sample.ID),
				zap.String("file", sample.FileName),
				zap.String("sha256", sample.Hashes.SHA256),
			)
		default:
			s.logger.Warn("detonation queue full, dropping sample",
				zap.String("id", sample.ID),
			)
		}
	}
}

// processSample performs detonation and analysis
func (s *Service) processSample(sample *models.DetonationSample) {
	s.logger.Info("processing sample",
		zap.String("id", sample.ID),
		zap.String("file", sample.FileName),
	)

	// Update status
	s.updateSampleStatus(sample.ID, models.DetonationStatusAnalyzing)

	// Perform static analysis
	staticAnalysis, err := s.analyzer.PerformStaticAnalysis(sample.FilePath)
	if err != nil {
		s.logger.Error("static analysis failed",
			zap.String("id", sample.ID),
			zap.Error(err),
		)
	}

	// Update status for detonation
	s.updateSampleStatus(sample.ID, models.DetonationStatusDetonating)

	// Perform sandbox detonation
	ctx, cancel := context.WithTimeout(s.ctx, s.config.DetonationTimeout)
	defer cancel()

	result, err := s.sandbox.Detonate(ctx, sample)
	if err != nil {
		s.logger.Error("detonation failed",
			zap.String("id", sample.ID),
			zap.Error(err),
		)
		s.updateSampleStatus(sample.ID, models.DetonationStatusFailed)
		return
	}

	// Generate report
	report := ConvertToReport(sample, result, staticAnalysis)
	report.ID = uuid.New().String()

	// Determine verdict
	sample.Verdict = s.determineVerdict(report)
	sample.Report = report
	sample.Status = models.DetonationStatusCompleted
	now := time.Now()
	sample.CompletedAt = &now

	// Save to storage
	if err := s.saveSample(sample); err != nil {
		s.logger.Error("failed to save sample", zap.String("id", sample.ID), zap.Error(err))
	}

	s.logger.Info("sample analysis complete",
		zap.String("id", sample.ID),
		zap.String("verdict", string(sample.Verdict)),
		zap.Int("threat_score", report.ThreatScore),
		zap.Duration("duration", report.Duration),
	)

	// Queue for portal upload
	if s.config.PortalUpload.Enabled && report.ThreatScore >= s.config.PortalUpload.MinThreatScore {
		s.queueForUpload(report)
	}
}

// determineVerdict assigns a verdict based on the analysis
func (s *Service) determineVerdict(report *models.DetonationReport) models.MalwareVerdict {
	score := report.ThreatScore

	switch {
	case score >= 80:
		return models.VerdictMalicious
	case score >= 50:
		return models.VerdictSuspicious
	case score >= 30:
		return models.VerdictPUA
	case score >= 10:
		return models.VerdictGrayware
	default:
		return models.VerdictClean
	}
}

// queueForUpload adds a report to the upload queue
func (s *Service) queueForUpload(report *models.DetonationReport) {
	s.uploadQueueMu.Lock()
	defer s.uploadQueueMu.Unlock()

	s.uploadQueue = append(s.uploadQueue, report)

	// Flush if batch size reached
	if len(s.uploadQueue) >= s.config.PortalUpload.BatchSize {
		go s.flushUploadQueue()
	}
}

// flushUploadQueue uploads pending reports to the portal
func (s *Service) flushUploadQueue() {
	s.uploadQueueMu.Lock()
	if len(s.uploadQueue) == 0 {
		s.uploadQueueMu.Unlock()
		return
	}
	reports := s.uploadQueue
	s.uploadQueue = nil
	s.uploadQueueMu.Unlock()

	s.logger.Info("uploading reports to portal", zap.Int("count", len(reports)))

	// Prepare payload for API
	payload := struct {
		Reports []*models.DetonationReport `json:"reports"`
	}{
		Reports: reports,
	}

	// Upload to AfterDark portal
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	if err := s.apiClient.Post(ctx, "/v1/detonation/reports", payload, nil); err != nil {
		s.logger.Error("failed to upload reports to portal",
			zap.Error(err),
			zap.Int("count", len(reports)),
		)
		// Re-queue failed reports
		s.uploadQueueMu.Lock()
		s.uploadQueue = append(reports, s.uploadQueue...)
		s.uploadQueueMu.Unlock()
		return
	}

	s.lastUpload = time.Now()
	s.logger.Info("successfully uploaded reports to portal",
		zap.Int("count", len(reports)),
	)

	// Mark samples as uploaded
	for _, report := range reports {
		s.markAsUploaded(report.SampleID)
	}
}

// Helper methods

func (s *Service) isSupportedType(ext string) bool {
	for _, supported := range s.config.SupportedTypes {
		if ext == supported {
			return true
		}
	}
	return false
}

func (s *Service) updateSampleStatus(id string, status models.DetonationStatus) {
	s.samplesMu.Lock()
	defer s.samplesMu.Unlock()
	if sample, ok := s.samples[id]; ok {
		sample.Status = status
	}
}

func (s *Service) updateFrequency(sample *models.DetonationSample) {
	// Query storage for existing samples with same hash
	key := fmt.Sprintf("sample_hash:%s", sample.Hashes.SHA256)
	data, err := s.store.Get(key)
	if err != nil {
		// First time seeing this hash
		sample.Frequency = models.SampleFrequency{
			TotalCount:      1,
			UniqueEndpoints: 1,
			UniqueRegions:   1,
			UniqueNetworks:  1,
			FirstSeen:       time.Now(),
			LastSeen:        time.Now(),
			SeenInLast24h:   1,
			SeenInLast7d:    1,
			SeenInLast30d:   1,
			TrendDirection:  "stable",
			PrevalenceScore: 1.0,
		}
		return
	}

	var freq models.SampleFrequency
	if err := json.Unmarshal(data, &freq); err != nil {
		return
	}

	// Update frequency
	freq.TotalCount++
	freq.LastSeen = time.Now()
	freq.SeenInLast24h++
	freq.SeenInLast7d++
	freq.SeenInLast30d++

	// Calculate trend
	if freq.SeenInLast24h > 5 {
		freq.TrendDirection = "increasing"
	}

	// Update prevalence score (simplified)
	freq.PrevalenceScore = float64(freq.UniqueEndpoints) / 100.0 * 100
	if freq.PrevalenceScore > 100 {
		freq.PrevalenceScore = 100
	}

	sample.Frequency = freq
}

func (s *Service) getLocationInfo(path string) models.SampleLocation {
	hostname, _ := os.Hostname()

	return models.SampleLocation{
		EndpointID:   s.getEndpointID(),
		Hostname:     hostname,
		Region:       s.getRegion(),
		NetworkZone:  s.getNetworkZone(),
		DetectedPath: path,
	}
}

func (s *Service) getEndpointID() string {
	// Read from storage or generate
	data, err := s.store.Get("endpoint_id")
	if err == nil {
		return string(data)
	}
	id := uuid.New().String()
	s.store.Set("endpoint_id", []byte(id))
	return id
}

func (s *Service) getRegion() string {
	// Could be set via config or auto-detected
	return "unknown"
}

func (s *Service) getNetworkZone() string {
	// Could be set via config or auto-detected
	return "default"
}

func (s *Service) saveSample(sample *models.DetonationSample) error {
	data, err := json.Marshal(sample)
	if err != nil {
		return err
	}

	// Save sample
	if err := s.store.Set(fmt.Sprintf("sample:%s", sample.ID), data); err != nil {
		return err
	}

	// Update frequency index
	freqData, _ := json.Marshal(sample.Frequency)
	s.store.Set(fmt.Sprintf("sample_hash:%s", sample.Hashes.SHA256), freqData)

	return nil
}

func (s *Service) markAsUploaded(sampleID string) {
	s.samplesMu.Lock()
	defer s.samplesMu.Unlock()
	if sample, ok := s.samples[sampleID]; ok {
		sample.UploadedToPortal = true
	}
}

func (s *Service) scanExistingFiles() {
	for _, dir := range s.config.WatchDirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			s.logger.Error("failed to read watch dir", zap.String("dir", dir), zap.Error(err))
			continue
		}

		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}
			path := filepath.Join(dir, entry.Name())
			s.handleNewFile(path)
		}
	}
}

// SubmitSample manually submits a file for analysis
func (s *Service) SubmitSample(path string) (*models.DetonationSample, error) {
	if !s.config.Enabled {
		return nil, fmt.Errorf("detonation chamber is disabled")
	}

	// Copy to quarantine
	filename := filepath.Base(path)
	quarantinePath := filepath.Join(s.config.QuarantineDir, filename)
	if err := copyFile(path, quarantinePath); err != nil {
		return nil, fmt.Errorf("failed to copy to quarantine: %w", err)
	}

	// Analyze
	sample, err := s.analyzer.AnalyzeFile(quarantinePath)
	if err != nil {
		return nil, err
	}

	sample.ID = uuid.New().String()
	sample.SubmittedAt = time.Now()
	sample.Location = s.getLocationInfo(path)

	// Queue for processing
	sample.Status = models.DetonationStatusQueued
	s.samplesMu.Lock()
	s.samples[sample.ID] = sample
	s.samplesMu.Unlock()

	s.queue <- sample

	return sample, nil
}

// GetSample retrieves a sample by ID
func (s *Service) GetSample(id string) (*models.DetonationSample, error) {
	s.samplesMu.RLock()
	sample, ok := s.samples[id]
	s.samplesMu.RUnlock()

	if ok {
		return sample, nil
	}

	// Try storage
	data, err := s.store.Get(fmt.Sprintf("sample:%s", id))
	if err != nil {
		return nil, fmt.Errorf("sample not found: %s", id)
	}

	var storedSample models.DetonationSample
	if err := json.Unmarshal(data, &storedSample); err != nil {
		return nil, err
	}

	return &storedSample, nil
}

// GetStats returns detonation statistics
func (s *Service) GetStats() map[string]interface{} {
	s.samplesMu.RLock()
	defer s.samplesMu.RUnlock()

	stats := map[string]interface{}{
		"total_samples":   len(s.samples),
		"queue_size":      len(s.queue),
		"active_workers":  len(s.semaphore),
		"max_concurrent":  s.config.MaxConcurrent,
		"last_upload":     s.lastUpload,
		"pending_uploads": len(s.uploadQueue),
	}

	// Count by status
	statusCounts := make(map[models.DetonationStatus]int)
	verdictCounts := make(map[models.MalwareVerdict]int)
	for _, sample := range s.samples {
		statusCounts[sample.Status]++
		verdictCounts[sample.Verdict]++
	}
	stats["by_status"] = statusCounts
	stats["by_verdict"] = verdictCounts

	return stats
}

// getVerdictFromScore converts a threat score to a verdict string
func getVerdictFromScore(score int) models.MalwareVerdict {
	switch {
	case score >= 80:
		return models.VerdictMalicious
	case score >= 50:
		return models.VerdictSuspicious
	case score >= 30:
		return models.VerdictPUA
	case score >= 10:
		return models.VerdictGrayware
	default:
		return models.VerdictClean
	}
}
