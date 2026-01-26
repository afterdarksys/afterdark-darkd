package memscan

import (
	"context"
	"math"
	"runtime"
	"sort"
	"sync"
	"time"

	"github.com/afterdarksys/afterdark-darkd/internal/models"
	"github.com/afterdarksys/afterdark-darkd/internal/service"
	"github.com/afterdarksys/afterdark-darkd/pkg/logging"
	"go.uber.org/zap"
)

// Service performs memory scanning for malware detection
type Service struct {
	mu      sync.RWMutex
	config  *models.MemoryScannerConfig
	running bool
	cancel  context.CancelFunc
	logger  *zap.Logger

	// Scan results
	scanResults map[int]*models.MemoryScanResult

	// Memory reader (platform-specific)
	reader MemoryReader

	// YARA scanner (if enabled)
	yaraScanner *YARAScanner

	// Scan semaphore for concurrency control
	scanSem chan struct{}

	// Process list from process tracker
	processList func() []models.ScanProcessInfo

	// Event callback
	onDetection func(*models.MemoryScanEvent)
}

// MemoryReader interface for platform-specific memory access
type MemoryReader interface {
	// ListProcesses returns valid PIDs for scanning
	ListProcesses() ([]models.ScanProcessInfo, error)

	// GetProcessInfo returns details for a PID
	GetProcessInfo(pid int) (*models.ScanProcessInfo, error)

	// GetMemoryRegions returns memory regions for a process
	GetMemoryRegions(pid int) ([]models.MemoryRegion, error)

	// ReadMemory reads memory from a process
	ReadMemory(pid int, address uint64, size uint64) ([]byte, error)

	// IsLSASS checks if process is LSASS (Windows)
	IsLSASS(pid int) bool
}

// New creates a new memory scanning service
func New(config *models.MemoryScannerConfig) *Service {
	return &Service{
		config:      config,
		scanResults: make(map[int]*models.MemoryScanResult),
		scanSem:     make(chan struct{}, config.MaxConcurrentScans),
		logger:      logging.Get().Named("memscan"),
	}
}

// Name returns the service identifier
func (s *Service) Name() string {
	return "memory_scanner"
}

// Start initializes and starts the service
func (s *Service) Start(ctx context.Context) error {
	s.mu.Lock()
	if s.running {
		s.mu.Unlock()
		return nil
	}

	s.running = true
	ctx, s.cancel = context.WithCancel(ctx)
	s.mu.Unlock()

	s.logger.Info("starting memory scanner service",
		zap.Duration("interval", s.config.ScanInterval),
		zap.Bool("scan_on_new_process", s.config.ScanOnNewProcess))

	// Initialize platform-specific reader
	var err error
	s.reader, err = NewPlatformReader(s.logger)
	if err != nil {
		s.logger.Error("failed to initialize memory reader", zap.Error(err))
		return err
	}

	// Initialize YARA scanner if enabled
	if s.config.YaraRulesDir != "" {
		s.yaraScanner, err = NewYARAScanner(s.config.YaraRulesDir, s.logger)
		if err != nil {
			s.logger.Warn("YARA scanner initialization failed", zap.Error(err))
		}
	}

	// Start scan loop
	go s.scanLoop(ctx)

	// Start cleanup loop
	go s.cleanupLoop(ctx)

	return nil
}

// Stop gracefully shuts down the service
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

	s.logger.Info("memory scanner service stopped")
	return nil
}

// Health returns the current health status
func (s *Service) Health() service.HealthStatus {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if !s.running {
		return service.HealthStatus{
			Status:    service.HealthUnhealthy,
			Message:   "service not running",
			LastCheck: time.Now(),
		}
	}

	metrics := make(map[string]interface{})
	metrics["scanned_processes"] = len(s.scanResults)
	metrics["detections"] = s.countDetections()

	return service.HealthStatus{
		Status:    service.HealthHealthy,
		Message:   "memory scanner active",
		LastCheck: time.Now(),
		Metrics:   metrics,
	}
}

// Configure updates service configuration
func (s *Service) Configure(config interface{}) error {
	if cfg, ok := config.(*models.MemoryScannerConfig); ok {
		s.mu.Lock()
		s.config = cfg
		s.mu.Unlock()
	}
	return nil
}

// scanLoop performs periodic memory scans
func (s *Service) scanLoop(ctx context.Context) {
	ticker := time.NewTicker(s.config.ScanInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.scanAllProcesses(ctx)
		}
	}
}

// cleanupLoop periodically removes old scan results
func (s *Service) cleanupLoop(ctx context.Context) {
	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.performCleanup()
		}
	}
}

// performCleanup removes results older than 24 hours
func (s *Service) performCleanup() {
	s.mu.Lock()
	defer s.mu.Unlock()

	retention := 24 * time.Hour
	threshold := time.Now().Add(-retention)

	initialCount := len(s.scanResults)
	for pid, result := range s.scanResults {
		if result.ScanTime.Before(threshold) {
			delete(s.scanResults, pid)
		}
	}

	removed := initialCount - len(s.scanResults)
	if removed > 0 {
		s.logger.Debug("cleaned up old scan results",
			zap.Int("removed_count", removed),
			zap.Int("remaining_count", len(s.scanResults)))
	}
}

// scanAllProcesses scans all target processes
func (s *Service) scanAllProcesses(ctx context.Context) {
	processes, err := s.reader.ListProcesses()
	if err != nil {
		s.logger.Error("failed to get process list", zap.Error(err))
		return
	}

	for _, proc := range processes {
		select {
		case <-ctx.Done():
			return
		default:
		}

		// Skip excluded processes
		if s.isExcluded(proc.Name) {
			continue
		}

		// Filter to target processes if specified
		if len(s.config.TargetProcesses) > 0 && !s.isTarget(proc.Name) {
			continue
		}

		// Acquire semaphore
		select {
		case s.scanSem <- struct{}{}:
		case <-ctx.Done():
			return
		}

		go func(p models.ScanProcessInfo) {
			defer func() { <-s.scanSem }()
			s.scanProcess(ctx, p)
		}(proc)
	}
}

// ScanProcess manually triggers a scan of a specific process
func (s *Service) ScanProcess(ctx context.Context, pid int) (*models.MemoryScanResult, error) {
	// Refresh process list
	processes, err := s.reader.ListProcesses()
	if err != nil {
		return nil, err
	}

	for _, proc := range processes {
		if proc.PID == pid {
			return s.scanProcess(ctx, proc), nil
		}
	}

	return nil, nil
}

// scanProcess scans a single process
func (s *Service) scanProcess(ctx context.Context, proc models.ScanProcessInfo) *models.MemoryScanResult {
	startTime := time.Now()

	result := &models.MemoryScanResult{
		PID:         proc.PID,
		ProcessName: proc.Name,
		ProcessPath: proc.Path,
		Username:    proc.Username,
		ScanTime:    startTime,
		ThreatLevel: "clean",
	}

	// Get memory regions
	regions, err := s.reader.GetMemoryRegions(proc.PID)
	if err != nil {
		s.logger.Debug("failed to get memory regions",
			zap.Int("pid", proc.PID),
			zap.Error(err))
		return nil
	}

	result.TotalRegions = len(regions)

	// Scan each region
	for _, region := range regions {
		select {
		case <-ctx.Done():
			return result
		default:
		}

		// Skip non-interesting regions
		if !s.shouldScanRegion(region) {
			continue
		}

		// Enforce memory limit
		if result.ScannedSize >= s.config.MaxMemoryPerScan {
			break
		}

		// Scan the region
		detections := s.scanRegion(ctx, proc.PID, region)
		if len(detections) > 0 {
			result.Detections = append(result.Detections, detections...)
		}

		// Check for suspicious region characteristics
		if s.isSuspiciousRegion(region) {
			result.SuspiciousRegions = append(result.SuspiciousRegions, region)
		}

		result.ScannedRegions++
		result.ScannedSize += int64(region.Size)
	}

	// Run YARA scan if available
	if s.yaraScanner != nil {
		yaraMatches := s.runYARAScan(ctx, proc.PID, regions)
		result.YARAMatches = yaraMatches
	}

	// Calculate threat score
	result.ThreatScore = s.calculateThreatScore(result)
	result.ThreatLevel = s.determineThreatLevel(result.ThreatScore)
	result.ScanDuration = time.Since(startTime)

	// Update detection flags
	for _, d := range result.Detections {
		switch d.Type {
		case models.DetectionShellcode:
			result.ShellcodeFound = true
		case models.DetectionInjection:
			result.InjectionDetected = true
		case models.DetectionHollowing:
			result.HollowingDetected = true
		}
	}

	// Store result
	s.mu.Lock()
	s.scanResults[proc.PID] = result
	s.mu.Unlock()

	// Fire event if threats detected
	if result.ThreatScore >= 50 && s.onDetection != nil {
		event := &models.MemoryScanEvent{
			Timestamp:      time.Now(),
			Result:         result,
			Action:         "detected",
			Severity:       result.ThreatLevel,
			MITRETechnique: s.getPrimaryMITRE(result),
		}
		go s.onDetection(event)
	}

	s.logger.Debug("process scan complete",
		zap.Int("pid", proc.PID),
		zap.String("process", proc.Name),
		zap.Int("detections", len(result.Detections)),
		zap.Float64("threat_score", result.ThreatScore))

	return result
}

// scanRegion scans a memory region for threats
func (s *Service) scanRegion(ctx context.Context, pid int, region models.MemoryRegion) []models.MemoryDetection {
	var detections []models.MemoryDetection

	// Check for RWX regions (code injection indicator)
	if s.config.CheckRWXRegions && region.Protection == models.ProtectionRWX {
		detections = append(detections, models.MemoryDetection{
			Type:        models.DetectionRWXRegion,
			Description: "Region with Read-Write-Execute permissions",
			Address:     region.BaseAddress,
			Size:        region.Size,
			Confidence:  0.6,
			TechniqueID: models.MITRET1055,
			Severity:    "medium",
			Indicators:  []string{"RWX permissions", "Potential code injection target"},
		})
	}

	// Check for unbacked executable code
	if s.config.CheckUnbackedCode && region.IsExecutable && region.IsUnbacked {
		detections = append(detections, models.MemoryDetection{
			Type:        models.DetectionUnbackedCode,
			Description: "Executable code without backing file",
			Address:     region.BaseAddress,
			Size:        region.Size,
			Confidence:  0.7,
			TechniqueID: models.MITRET1620,
			Severity:    "high",
			Indicators:  []string{"Unbacked executable", "Potential reflective loading"},
		})
	}

	// Read and analyze memory content
	if region.Size <= uint64(s.config.MaxMemoryPerScan) {
		data, err := s.reader.ReadMemory(pid, region.BaseAddress, min64(region.Size, 65536))
		if err == nil && len(data) > 0 {
			// Check for PE header in non-image region
			if region.Type != models.RegionTypeImage && containsPEHeader(data) {
				detections = append(detections, models.MemoryDetection{
					Type:        models.DetectionPEHeader,
					Description: "PE header found in non-image memory region",
					Address:     region.BaseAddress,
					Size:        region.Size,
					Confidence:  0.85,
					TechniqueID: models.MITRET1620,
					Severity:    "high",
					Indicators:  []string{"MZ header", "PE signature", "Reflective DLL injection"},
				})
			}

			// Check for ELF header in non-image region (Linux)
			if region.Type != models.RegionTypeImage && containsELFHeader(data) {
				detections = append(detections, models.MemoryDetection{
					Type:        models.DetectionELFHeader,
					Description: "ELF header found in non-image memory region",
					Address:     region.BaseAddress,
					Size:        region.Size,
					Confidence:  0.85,
					TechniqueID: models.MITRET1620,
					Severity:    "high",
					Indicators:  []string{"ELF magic", "Reflective loading"},
				})
			}

			// Check for shellcode patterns
			if shellcodeDetection := s.detectShellcode(data, region); shellcodeDetection != nil {
				shellcodeDetection.Address = region.BaseAddress
				detections = append(detections, *shellcodeDetection)
			}
		}
	}

	return detections
}

// detectShellcode scans for shellcode patterns
func (s *Service) detectShellcode(data []byte, region models.MemoryRegion) *models.MemoryDetection {
	if len(data) < 8 {
		return nil
	}

	var indicators []string
	totalScore := 0.0

	// Check against known shellcode signatures
	for _, sig := range models.CommonShellcodeSignatures {
		for _, pattern := range sig.Patterns {
			if containsPattern(data, pattern) {
				indicators = append(indicators, sig.Description)
				totalScore += sig.Confidence * 20
			}
		}
	}

	// Check entropy (shellcode often has high entropy)
	entropy := calculateEntropy(data)
	if entropy > 7.0 && region.IsExecutable {
		indicators = append(indicators, "High entropy in executable region")
		totalScore += 15
	}

	// Check for API hashing patterns
	if hasAPIHashingPattern(data) {
		indicators = append(indicators, "API hashing detected")
		totalScore += 25
	}

	if totalScore >= 30 {
		return &models.MemoryDetection{
			Type:        models.DetectionShellcode,
			Description: "Potential shellcode detected",
			Size:        uint64(len(data)),
			Confidence:  math.Min(totalScore/100, 1.0),
			TechniqueID: models.MITRET1055,
			Severity:    s.scoreToSeverity(totalScore),
			Indicators:  indicators,
		}
	}

	return nil
}

// runYARAScan runs YARA rules against process memory
func (s *Service) runYARAScan(ctx context.Context, pid int, regions []models.MemoryRegion) []models.YARAMatch {
	if s.yaraScanner == nil {
		return nil
	}

	var matches []models.YARAMatch

	for _, region := range regions {
		if !region.IsExecutable && region.Type != models.RegionTypePrivate {
			continue
		}

		data, err := s.reader.ReadMemory(pid, region.BaseAddress, min64(region.Size, 1024*1024))
		if err != nil || len(data) == 0 {
			continue
		}

		regionMatches := s.yaraScanner.Scan(data, region.BaseAddress)
		matches = append(matches, regionMatches...)
	}

	return matches
}

// shouldScanRegion determines if a region should be scanned
func (s *Service) shouldScanRegion(region models.MemoryRegion) bool {
	// Always scan executable regions
	if region.IsExecutable {
		return true
	}

	// Scan private writable regions (potential injection targets)
	if region.Type == models.RegionTypePrivate && region.IsWritable {
		return true
	}

	// Scan RWX regions
	if region.Protection == models.ProtectionRWX {
		return true
	}

	return false
}

// isSuspiciousRegion checks if a region has suspicious characteristics
func (s *Service) isSuspiciousRegion(region models.MemoryRegion) bool {
	// RWX is always suspicious
	if region.Protection == models.ProtectionRWX {
		return true
	}

	// Executable without backing file
	if region.IsExecutable && region.IsUnbacked {
		return true
	}

	// High entropy in executable region
	if region.IsExecutable && region.Entropy > 7.5 {
		return true
	}

	return false
}

// calculateThreatScore calculates overall threat score
func (s *Service) calculateThreatScore(result *models.MemoryScanResult) float64 {
	score := 0.0

	// Score from detections
	for _, d := range result.Detections {
		score += d.Confidence * 30
	}

	// Score from YARA matches
	score += float64(len(result.YARAMatches)) * 20

	// Score from suspicious regions
	score += float64(len(result.SuspiciousRegions)) * 5

	return math.Min(score, 100)
}

// determineThreatLevel converts score to threat level
func (s *Service) determineThreatLevel(score float64) string {
	if score >= 80 {
		return "critical"
	}
	if score >= 60 {
		return "high"
	}
	if score >= 40 {
		return "medium"
	}
	if score >= 20 {
		return "low"
	}
	return "clean"
}

// scoreToSeverity converts a numeric score to severity string
func (s *Service) scoreToSeverity(score float64) string {
	if score >= 70 {
		return "critical"
	}
	if score >= 50 {
		return "high"
	}
	if score >= 30 {
		return "medium"
	}
	return "low"
}

// getPrimaryMITRE returns the primary MITRE technique for a scan result
func (s *Service) getPrimaryMITRE(result *models.MemoryScanResult) string {
	if result.InjectionDetected {
		return models.MITRET1055
	}
	if result.HollowingDetected {
		return models.MITRET1055012
	}
	if result.ShellcodeFound {
		return models.MITRET1055
	}
	return models.MITRET1055
}

// isExcluded checks if a process name is excluded
func (s *Service) isExcluded(name string) bool {
	for _, excluded := range s.config.ExcludeProcesses {
		if name == excluded {
			return true
		}
	}
	return false
}

// isTarget checks if a process name is in target list
func (s *Service) isTarget(name string) bool {
	for _, target := range s.config.TargetProcesses {
		if name == target {
			return true
		}
	}
	return false
}

// countDetections counts total detections across all scanned processes
func (s *Service) countDetections() int {
	count := 0
	for _, result := range s.scanResults {
		count += len(result.Detections)
	}
	return count
}

// GetScanResults returns all scan results
func (s *Service) GetScanResults() map[int]*models.MemoryScanResult {
	s.mu.RLock()
	defer s.mu.RUnlock()

	results := make(map[int]*models.MemoryScanResult)
	for k, v := range s.scanResults {
		results[k] = v
	}
	return results
}

// GetDetections returns all processes with detections
func (s *Service) GetDetections() []*models.MemoryScanResult {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var detected []*models.MemoryScanResult
	for _, result := range s.scanResults {
		if len(result.Detections) > 0 || len(result.YARAMatches) > 0 {
			detected = append(detected, result)
		}
	}

	// Sort by threat score
	sort.Slice(detected, func(i, j int) bool {
		return detected[i].ThreatScore > detected[j].ThreatScore
	})

	return detected
}

// OnDetection sets the callback for detection events
func (s *Service) OnDetection(callback func(*models.MemoryScanEvent)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.onDetection = callback
}

// Helper functions

func containsPEHeader(data []byte) bool {
	if len(data) < 64 {
		return false
	}
	// Check for MZ header
	if data[0] != 'M' || data[1] != 'Z' {
		return false
	}
	// Check PE offset
	peOffset := int(data[0x3C]) | int(data[0x3D])<<8
	if peOffset < 0 || peOffset+4 > len(data) {
		return false
	}
	// Check for PE signature
	return data[peOffset] == 'P' && data[peOffset+1] == 'E' &&
		data[peOffset+2] == 0 && data[peOffset+3] == 0
}

func containsELFHeader(data []byte) bool {
	if len(data) < 4 {
		return false
	}
	// ELF magic: 0x7f 'E' 'L' 'F'
	return data[0] == 0x7f && data[1] == 'E' && data[2] == 'L' && data[3] == 'F'
}

func containsPattern(data, pattern []byte) bool {
	if len(pattern) > len(data) {
		return false
	}
	for i := 0; i <= len(data)-len(pattern); i++ {
		match := true
		for j := 0; j < len(pattern); j++ {
			if data[i+j] != pattern[j] {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}

func calculateEntropy(data []byte) float64 {
	if len(data) == 0 {
		return 0
	}

	freq := make(map[byte]float64)
	for _, b := range data {
		freq[b]++
	}

	var entropy float64
	length := float64(len(data))
	for _, count := range freq {
		p := count / length
		entropy -= p * math.Log2(p)
	}

	return entropy
}

func hasAPIHashingPattern(data []byte) bool {
	// Look for common API hashing constants
	// ROR13 hash patterns, etc.
	hashPatterns := [][]byte{
		{0xc1, 0xc8, 0x0d}, // ror eax, 0xd (common hash rotation)
		{0xc1, 0xcf, 0x0d}, // ror edi, 0xd
	}

	for _, pattern := range hashPatterns {
		if containsPattern(data, pattern) {
			return true
		}
	}
	return false
}

func min64(a, b uint64) uint64 {
	if a < b {
		return a
	}
	return b
}

// NewPlatformReader creates a platform-specific memory reader
func NewPlatformReader(logger *zap.Logger) (MemoryReader, error) {
	switch runtime.GOOS {
	case "linux":
		return NewLinuxReader(logger)
	case "darwin":
		return NewDarwinReader(logger)
	case "windows":
		return NewWindowsReader(logger)
	default:
		return NewLinuxReader(logger) // Fallback
	}
}
