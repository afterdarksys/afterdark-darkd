package dnstunnel

import (
	"context"
	"math"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/afterdarksys/afterdark-darkd/internal/models"
	"github.com/afterdarksys/afterdark-darkd/internal/service"
	"github.com/afterdarksys/afterdark-darkd/pkg/logging"
	"go.uber.org/zap"
)

// Service detects DNS tunneling attempts
type Service struct {
	mu      sync.RWMutex
	config  *models.DNSTunnelConfig
	running bool
	cancel  context.CancelFunc
	logger  *zap.Logger

	// Domain statistics
	domainStats map[string]*models.DNSDomainStats

	// Analysis results
	analysisResults map[string]*models.DNSTunnelAnalysis

	// Whitelisted domains
	whitelist map[string]bool

	// DNS capture (platform-specific)
	capture DNSCapture

	// Event callback
	onTunnelDetected func(*models.DNSTunnelEvent)
}

// DNSCapture interface for platform-specific DNS capture
type DNSCapture interface {
	Start(ctx context.Context) error
	Stop() error
	Queries() <-chan models.TunnelDNSQuery
}

// New creates a new DNS tunnel detection service
func New(config *models.DNSTunnelConfig) *Service {
	whitelist := make(map[string]bool)
	for _, domain := range config.WhitelistDomains {
		whitelist[strings.ToLower(domain)] = true
	}

	return &Service{
		config:          config,
		domainStats:     make(map[string]*models.DNSDomainStats),
		analysisResults: make(map[string]*models.DNSTunnelAnalysis),
		whitelist:       whitelist,
		logger:          logging.Get().Named("dnstunnel"),
	}
}

// Name returns the service identifier
func (s *Service) Name() string {
	return "dns_tunnel_detection"
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

	s.logger.Info("starting DNS tunnel detection service",
		zap.String("capture_method", s.config.CaptureMethod),
		zap.Duration("analysis_window", s.config.AnalysisWindow))

	// Initialize capture based on method
	var err error
	s.capture, err = s.initCapture()
	if err != nil {
		s.logger.Warn("DNS capture initialization failed, using passive mode",
			zap.Error(err))
	}

	// Start capture if available
	if s.capture != nil {
		if err := s.capture.Start(ctx); err != nil {
			s.logger.Warn("DNS capture start failed", zap.Error(err))
		} else {
			go s.processQueries(ctx)
		}
	}

	// Start analysis loop
	go s.analysisLoop(ctx)

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

	if s.capture != nil {
		s.capture.Stop()
	}

	s.logger.Info("DNS tunnel detection service stopped")
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
	metrics["tracked_domains"] = len(s.domainStats)
	metrics["detected_tunnels"] = s.countDetectedTunnels()

	return service.HealthStatus{
		Status:    service.HealthHealthy,
		Message:   "DNS tunnel detection active",
		LastCheck: time.Now(),
		Metrics:   metrics,
	}
}

// Configure updates service configuration
func (s *Service) Configure(config interface{}) error {
	if cfg, ok := config.(*models.DNSTunnelConfig); ok {
		s.mu.Lock()
		s.config = cfg

		// Update whitelist
		s.whitelist = make(map[string]bool)
		for _, domain := range cfg.WhitelistDomains {
			s.whitelist[strings.ToLower(domain)] = true
		}

		s.mu.Unlock()
	}
	return nil
}

// initCapture initializes the DNS capture method
func (s *Service) initCapture() (DNSCapture, error) {
	switch s.config.CaptureMethod {
	case "pcap":
		return NewPcapCapture(s.logger)
	case "logs":
		return NewLogCapture(s.logger)
	case "etw":
		return NewETWCapture(s.logger)
	default:
		return NewLogCapture(s.logger)
	}
}

// processQueries processes incoming DNS queries
func (s *Service) processQueries(ctx context.Context) {
	if s.capture == nil {
		return
	}

	queryChan := s.capture.Queries()
	for {
		select {
		case <-ctx.Done():
			return
		case query, ok := <-queryChan:
			if !ok {
				return
			}
			s.recordQuery(query)
		}
	}
}

// RecordQuery manually records a DNS query (for external integration)
func (s *Service) RecordQuery(query models.TunnelDNSQuery) {
	s.recordQuery(query)
}

// ProcessQuery processes a new DNS query
func (s *Service) ProcessQuery(q models.TunnelDNSQuery) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Parse domain
	baseDomain := extractBaseDomain(q.Domain)

	// Skip whitelisted domains
	if s.isWhitelisted(baseDomain) {
		return
	}

	// Initialize stats if new
	if _, exists := s.domainStats[baseDomain]; !exists {
		s.domainStats[baseDomain] = &models.DNSDomainStats{
			Domain:    baseDomain,
			FirstSeen: q.Timestamp,
		}
	}

	// Extract subdomain
	q.Subdomain = extractSubdomain(q.Domain, baseDomain)

	// Add query to stats
	s.domainStats[baseDomain].AddQuery(q)
}

// recordQuery records a DNS query for analysis
func (s *Service) recordQuery(query models.TunnelDNSQuery) {
	baseDomain := extractBaseDomain(query.Domain)

	// Skip whitelisted domains
	if s.isWhitelisted(baseDomain) {
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.domainStats[baseDomain]; !exists {
		s.domainStats[baseDomain] = &models.DNSDomainStats{
			Domain: baseDomain,
		}
	}

	// Extract subdomain
	query.Subdomain = extractSubdomain(query.Domain, baseDomain)

	s.domainStats[baseDomain].AddQuery(query)
}

// analysisLoop periodically analyzes domains for tunneling
func (s *Service) analysisLoop(ctx context.Context) {
	ticker := time.NewTicker(s.config.CheckInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.analyzeAllDomains()
		}
	}
}

// analyzeAllDomains analyzes all tracked domains for tunneling
func (s *Service) analyzeAllDomains() {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	windowStart := now.Add(-s.config.AnalysisWindow)

	for domain, stats := range s.domainStats {
		// Skip if not enough queries
		recentQueries := s.filterRecentQueries(stats.Queries, s.config.AnalysisWindow)
		if len(recentQueries) < 10 {
			continue
		}

		// Analyze domain
		analysis := s.analyzeDomain(domain, stats, recentQueries)
		if analysis != nil {
			s.analysisResults[domain] = analysis

			// Fire event if tunnel detected
			if analysis.IsTunnelLikely && s.onTunnelDetected != nil {
				event := &models.DNSTunnelEvent{
					Timestamp:      now,
					Analysis:       analysis,
					Action:         "detected",
					Severity:       s.calculateSeverity(analysis),
					MITRETechnique: "T1071.004", // Application Layer Protocol: DNS
					SampleQueries:  recentQueries[:min(5, len(recentQueries))],
				}
				go s.onTunnelDetected(event)
			}
		}
	}

	// Cleanup old data
	s.cleanup(windowStart)
}

// analyzeDomain analyzes a single domain for tunneling indicators
func (s *Service) analyzeDomain(domain string, stats *models.DNSDomainStats, queries []models.TunnelDNSQuery) *models.DNSTunnelAnalysis {
	if len(queries) == 0 {
		return nil
	}
	analysis := &models.DNSTunnelAnalysis{
		Domain:       domain,
		BaseDomain:   domain,
		QueryCount:   len(queries),
		FirstSeen:    stats.FirstSeen,
		LastQuery:    stats.LastSeen,
		LastAnalyzed: time.Now(),
	}

	// Extract subdomains for analysis
	subdomains := make([]string, 0, len(queries))
	for _, q := range queries {
		if q.Subdomain != "" {
			subdomains = append(subdomains, q.Subdomain)
		}
	}

	if len(subdomains) == 0 {
		return nil
	}

	// Calculate subdomain statistics
	analysis.UniqueSubdomains = len(stats.Subdomains)
	analysis.AvgSubdomainLen, analysis.MaxSubdomainLen = s.calculateSubdomainLengths(subdomains)

	// Calculate entropy metrics
	analysis.AvgEntropy, analysis.MaxEntropy, analysis.MinEntropy = s.calculateEntropyMetrics(subdomains)

	// Calculate query rate
	duration := stats.LastSeen.Sub(stats.FirstSeen)
	if duration > 0 {
		analysis.QueriesPerMinute = float64(len(queries)) / duration.Minutes()
	}

	// Calculate record type ratios
	totalQueries := float64(len(queries))
	if txtCount, ok := stats.RecordTypes[models.DNSRecordTXT]; ok {
		analysis.TXTQueryRatio = float64(txtCount) / totalQueries
	}
	if nullCount, ok := stats.RecordTypes[models.DNSRecordNULL]; ok {
		analysis.NULLQueryCount = nullCount
	}

	// Calculate NXDOMAIN ratio
	if nxCount, ok := stats.ResponseCodes[models.DNSResponseNXDOMAIN]; ok {
		analysis.NXDOMAINRatio = float64(nxCount) / totalQueries
	}

	// Detect encoding
	analysis.EncodingDetected, analysis.EncodingScore = s.detectEncoding(subdomains)

	// Calculate tunneling score
	analysis.TunnelingScore = s.calculateTunnelingScore(analysis)
	analysis.IsTunnelLikely = analysis.TunnelingScore >= s.config.TunnelScoreThreshold

	// Match against known tools
	analysis.TunnelType, analysis.Confidence = s.matchTunnelingTool(analysis)

	return analysis
}

// calculateSubdomainLengths calculates average and max subdomain lengths
func (s *Service) calculateSubdomainLengths(subdomains []string) (avg float64, max int) {
	if len(subdomains) == 0 {
		return 0, 0
	}

	total := 0
	for _, sub := range subdomains {
		length := len(sub)
		total += length
		if length > max {
			max = length
		}
	}

	return float64(total) / float64(len(subdomains)), max
}

// calculateEntropyMetrics calculates Shannon entropy metrics
func (s *Service) calculateEntropyMetrics(subdomains []string) (avg, max, min float64) {
	if len(subdomains) == 0 {
		return 0, 0, 0
	}

	min = math.MaxFloat64
	total := 0.0

	for _, sub := range subdomains {
		entropy := calculateShannonEntropy(sub)
		total += entropy
		if entropy > max {
			max = entropy
		}
		if entropy < min {
			min = entropy
		}
	}

	return total / float64(len(subdomains)), max, min
}

// calculateShannonEntropy calculates Shannon entropy for a string
func calculateShannonEntropy(s string) float64 {
	if len(s) == 0 {
		return 0
	}

	// Count character frequencies
	freq := make(map[rune]float64)
	for _, c := range s {
		freq[c]++
	}

	// Calculate entropy
	var entropy float64
	length := float64(len(s))
	for _, count := range freq {
		p := count / length
		entropy -= p * math.Log2(p)
	}

	return entropy
}

// detectEncoding detects what encoding might be used in subdomains
func (s *Service) detectEncoding(subdomains []string) (string, float64) {
	if len(subdomains) == 0 {
		return "none", 0
	}

	// Encoding detection patterns
	base64Pattern := regexp.MustCompile(`^[A-Za-z0-9+/=]+$`)
	base32Pattern := regexp.MustCompile(`^[A-Z2-7=]+$`)
	hexPattern := regexp.MustCompile(`^[0-9a-fA-F]+$`)

	var base64Count, base32Count, hexCount int

	for _, sub := range subdomains {
		// Remove common separators
		clean := strings.ReplaceAll(sub, ".", "")
		clean = strings.ReplaceAll(clean, "-", "")

		if len(clean) < 4 {
			continue
		}

		if hexPattern.MatchString(clean) {
			hexCount++
		}
		if base32Pattern.MatchString(strings.ToUpper(clean)) {
			base32Count++
		}
		if base64Pattern.MatchString(clean) {
			base64Count++
		}
	}

	total := float64(len(subdomains))
	hexRatio := float64(hexCount) / total
	base32Ratio := float64(base32Count) / total
	base64Ratio := float64(base64Count) / total

	// Return the most likely encoding
	if hexRatio > 0.7 {
		return "hex", hexRatio
	}
	if base32Ratio > 0.7 {
		return "base32", base32Ratio
	}
	if base64Ratio > 0.7 {
		return "base64", base64Ratio
	}

	return "none", 0
}

// calculateTunnelingScore calculates overall tunneling likelihood
func (s *Service) calculateTunnelingScore(analysis *models.DNSTunnelAnalysis) float64 {
	score := 0.0

	// High entropy subdomains (tunneled data is high entropy)
	// Normal: 2.5-3.5, Tunneled: 4.0-5.0, Random/encrypted: 5.5+
	if analysis.AvgEntropy > 4.5 {
		score += 30
	} else if analysis.AvgEntropy > 4.0 {
		score += 25
	} else if analysis.AvgEntropy > 3.5 {
		score += 15
	}

	// Long subdomains (tunneling maximizes data per query)
	if analysis.AvgSubdomainLen > 40 {
		score += 25
	} else if analysis.AvgSubdomainLen > 30 {
		score += 20
	} else if analysis.AvgSubdomainLen > 20 {
		score += 10
	}

	// Many unique subdomains (data encoded in subdomain)
	if analysis.UniqueSubdomains > 100 {
		score += 15
	} else if analysis.UniqueSubdomains > 50 {
		score += 10
	}

	// TXT record abuse (preferred for large data transfer)
	if analysis.TXTQueryRatio > 0.5 {
		score += 15
	} else if analysis.TXTQueryRatio > 0.3 {
		score += 10
	}

	// NULL record usage (often used by iodine)
	if analysis.NULLQueryCount > 0 {
		score += 10
	}

	// Detected encoding pattern
	if analysis.EncodingDetected != "none" && analysis.EncodingScore > 0.5 {
		score += 15
	}

	// High query rate
	if analysis.QueriesPerMinute > 10 {
		score += 10
	} else if analysis.QueriesPerMinute > 5 {
		score += 5
	}

	// NXDOMAIN responses (may indicate domain generation)
	if analysis.NXDOMAINRatio > 0.3 {
		score += 5
	}

	return math.Min(score, 100)
}

// matchTunnelingTool matches against known tunneling tool signatures
func (s *Service) matchTunnelingTool(analysis *models.DNSTunnelAnalysis) (string, float64) {
	bestMatch := "unknown"
	bestScore := 0.0

	for _, tool := range models.KnownDNSTunnelingTools {
		matchScore := 0.0

		// Check subdomain length range
		if int(analysis.AvgSubdomainLen) >= tool.SubdomainLen[0] &&
			int(analysis.AvgSubdomainLen) <= tool.SubdomainLen[1] {
			matchScore += 20
		}

		// Check entropy range
		if analysis.AvgEntropy >= tool.EntropyRange[0] &&
			analysis.AvgEntropy <= tool.EntropyRange[1] {
			matchScore += 25
		}

		// Check encoding match
		if analysis.EncodingDetected == tool.Encoding {
			matchScore += 30
		}

		// Specific tool checks
		switch tool.Name {
		case "iodine":
			if analysis.NULLQueryCount > 0 {
				matchScore += 20
			}
			if analysis.MaxSubdomainLen > 100 {
				matchScore += 10
			}
		case "dnscat2":
			if analysis.EncodingDetected == "hex" {
				matchScore += 15
			}
		case "dns2tcp":
			if analysis.TXTQueryRatio > 0.5 {
				matchScore += 15
			}
		}

		if matchScore > bestScore {
			bestScore = matchScore
			bestMatch = tool.Name
		}
	}

	confidence := bestScore / 100.0
	if bestScore < 40 {
		return "unknown", confidence
	}

	return bestMatch, confidence
}

// calculateSeverity determines alert severity based on analysis
func (s *Service) calculateSeverity(analysis *models.DNSTunnelAnalysis) string {
	if analysis.TunnelingScore >= 90 {
		return "critical"
	}
	if analysis.TunnelingScore >= 75 {
		return "high"
	}
	if analysis.TunnelingScore >= 60 {
		return "medium"
	}
	return "low"
}

// isWhitelisted checks if a domain is whitelisted
func (s *Service) isWhitelisted(domain string) bool {
	domain = strings.ToLower(domain)

	if s.whitelist[domain] {
		return true
	}

	// Check wildcard patterns
	for pattern := range s.whitelist {
		if matchesWildcard(pattern, domain) {
			return true
		}
	}

	return false
}

// matchesWildcard checks if domain matches a wildcard pattern
func matchesWildcard(pattern, domain string) bool {
	if len(pattern) > 0 && pattern[0] == '*' {
		suffix := pattern[1:]
		return strings.HasSuffix(domain, suffix)
	}
	return pattern == domain
}

// filterRecentQueries filters queries within the analysis window
func (s *Service) filterRecentQueries(queries []models.TunnelDNSQuery, duration time.Duration) []models.TunnelDNSQuery {
	var recent []models.TunnelDNSQuery
	threshold := time.Now().Add(-duration)

	for _, q := range queries {
		if q.Timestamp.After(threshold) {
			recent = append(recent, q)
		}
	}
	return recent
}

// cleanup removes old domain statistics
func (s *Service) cleanup(before time.Time) {
	for domain, stats := range s.domainStats {
		if stats.LastSeen.Before(before) {
			delete(s.domainStats, domain)
			delete(s.analysisResults, domain)
		}
	}
}

// countDetectedTunnels counts domains flagged as tunnels
func (s *Service) countDetectedTunnels() int {
	count := 0
	for _, analysis := range s.analysisResults {
		if analysis.IsTunnelLikely {
			count++
		}
	}
	return count
}

// GetAnalysisResults returns all analysis results
func (s *Service) GetAnalysisResults() map[string]*models.DNSTunnelAnalysis {
	s.mu.RLock()
	defer s.mu.RUnlock()

	results := make(map[string]*models.DNSTunnelAnalysis)
	for k, v := range s.analysisResults {
		results[k] = v
	}
	return results
}

// GetDetectedTunnels returns only domains flagged as likely tunnels
func (s *Service) GetDetectedTunnels() []*models.DNSTunnelAnalysis {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var tunnels []*models.DNSTunnelAnalysis
	for _, analysis := range s.analysisResults {
		if analysis.IsTunnelLikely {
			tunnels = append(tunnels, analysis)
		}
	}

	// Sort by score
	sort.Slice(tunnels, func(i, j int) bool {
		return tunnels[i].TunnelingScore > tunnels[j].TunnelingScore
	})

	return tunnels
}

// OnTunnelDetected sets the callback for tunnel detection events
func (s *Service) OnTunnelDetected(callback func(*models.DNSTunnelEvent)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.onTunnelDetected = callback
}

// Helper functions

func extractBaseDomain(domain string) string {
	// Simple extraction - get last two parts
	// For production, use a proper public suffix list
	parts := strings.Split(strings.ToLower(domain), ".")
	if len(parts) >= 2 {
		return strings.Join(parts[len(parts)-2:], ".")
	}
	return domain
}

func extractSubdomain(fullDomain, baseDomain string) string {
	fullDomain = strings.ToLower(fullDomain)
	baseDomain = strings.ToLower(baseDomain)

	if strings.HasSuffix(fullDomain, "."+baseDomain) {
		return strings.TrimSuffix(fullDomain, "."+baseDomain)
	}
	if fullDomain == baseDomain {
		return ""
	}
	return fullDomain
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
