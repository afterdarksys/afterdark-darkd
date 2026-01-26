package conntrack

import (
	"math"
	"sort"
	"sync"
	"time"

	"github.com/afterdarksys/afterdark-darkd/internal/models"
	"go.uber.org/zap"
)

// BeaconAnalyzer detects C2 beaconing patterns in network connections
type BeaconAnalyzer struct {
	mu     sync.RWMutex
	config *models.C2DetectionConfig
	logger *zap.Logger

	// Connection timing data
	timingData map[string]*models.ConnectionTiming

	// Analysis results
	beaconAnalysis map[string]*models.BeaconAnalysis

	// Whitelisted destinations
	whitelist map[string]bool
}

// NewBeaconAnalyzer creates a new beacon analyzer
func NewBeaconAnalyzer(config *models.C2DetectionConfig, logger *zap.Logger) *BeaconAnalyzer {
	whitelist := make(map[string]bool)
	for _, dest := range config.KnownGoodDestinations {
		whitelist[dest] = true
	}

	return &BeaconAnalyzer{
		config:         config,
		logger:         logger.Named("beacon"),
		timingData:     make(map[string]*models.ConnectionTiming),
		beaconAnalysis: make(map[string]*models.BeaconAnalysis),
		whitelist:      whitelist,
	}
}

// RecordConnection records a connection timestamp for beacon analysis
func (b *BeaconAnalyzer) RecordConnection(key string, conn *models.NetworkConnection, bytesSent, bytesRecv int64) {
	b.mu.Lock()
	defer b.mu.Unlock()

	// Skip whitelisted destinations
	if b.isWhitelisted(conn.RemoteAddr) {
		return
	}

	if _, exists := b.timingData[key]; !exists {
		b.timingData[key] = &models.ConnectionTiming{}
	}

	b.timingData[key].AddTimestamp(time.Now(), bytesSent, bytesRecv)
}

// AnalyzeBeacons analyzes all tracked connections for beaconing behavior
func (b *BeaconAnalyzer) AnalyzeBeacons(trackedConns map[string]*models.TrackedConnection) []*models.BeaconAnalysis {
	b.mu.Lock()
	defer b.mu.Unlock()

	var results []*models.BeaconAnalysis

	for key, timing := range b.timingData {
		// Need minimum connections for analysis
		if timing.GetIntervalCount() < b.config.MinConnections {
			continue
		}

		// Get tracked connection info
		tracked, exists := trackedConns[key]
		if !exists {
			continue
		}

		// Analyze the timing pattern
		analysis := b.analyzeTimingPattern(key, timing, tracked)
		if analysis != nil {
			b.beaconAnalysis[key] = analysis

			if analysis.IsBeaconLikely {
				results = append(results, analysis)
			}
		}
	}

	// Sort by beacon score descending
	sort.Slice(results, func(i, j int) bool {
		return results[i].BeaconScore > results[j].BeaconScore
	})

	return results
}

// analyzeTimingPattern analyzes connection timing for beacon patterns
func (b *BeaconAnalyzer) analyzeTimingPattern(key string, timing *models.ConnectionTiming, tracked *models.TrackedConnection) *models.BeaconAnalysis {
	intervals := timing.Intervals
	if len(intervals) < b.config.MinConnections {
		return nil
	}

	// Calculate statistics
	mean := b.calculateMean(intervals)
	stdDev := b.calculateStdDev(intervals, mean)
	cov := stdDev / float64(mean) // Coefficient of Variation

	// Calculate jitter percentage
	jitter := b.calculateJitter(intervals, mean)

	// Calculate beacon score
	score := b.calculateBeaconScore(mean, stdDev, cov, jitter, len(intervals), timing)

	// Check for known C2 framework matches
	matchedFramework, frameworkScore := b.matchC2Framework(mean, cov, jitter, int(tracked.Key.RemotePort))
	score += frameworkScore

	// Detect pattern type
	patternType := b.detectPatternType(intervals, cov, jitter)

	analysis := &models.BeaconAnalysis{
		ConnectionKey:    key,
		RemoteAddr:       tracked.Key.RemoteAddr,
		RemotePort:       int(tracked.Key.RemotePort),
		ProcessName:      tracked.ProcessName,
		ProcessPID:       int(tracked.PID),
		MeanInterval:     mean,
		StdDeviation:     stdDev,
		CoeffVariation:   cov,
		JitterPercent:    jitter,
		ConnectionCount:  len(intervals) + 1,
		AvgBytesOut:      b.calculateMeanInt64(timing.BytesSent),
		AvgBytesIn:       b.calculateMeanInt64(timing.BytesReceived),
		BeaconScore:      math.Min(score, 100),
		IsBeaconLikely:   score >= b.config.BeaconThreshold,
		DetectedPattern:  patternType,
		MatchedFramework: matchedFramework,
		Confidence:       score / 100.0,
		FirstSeen:        tracked.FirstSeen,
		LastSeen:         tracked.LastSeen,
		LastAnalyzed:     time.Now(),
	}

	return analysis
}

// calculateMean calculates the mean of duration intervals
func (b *BeaconAnalyzer) calculateMean(intervals []time.Duration) time.Duration {
	if len(intervals) == 0 {
		return 0
	}

	var total time.Duration
	for _, interval := range intervals {
		total += interval
	}

	return total / time.Duration(len(intervals))
}

// calculateStdDev calculates standard deviation
func (b *BeaconAnalyzer) calculateStdDev(intervals []time.Duration, mean time.Duration) float64 {
	if len(intervals) == 0 {
		return 0
	}

	var sumSquares float64
	meanFloat := float64(mean)

	for _, interval := range intervals {
		diff := float64(interval) - meanFloat
		sumSquares += diff * diff
	}

	variance := sumSquares / float64(len(intervals))
	return math.Sqrt(variance)
}

// calculateJitter calculates jitter as a percentage
func (b *BeaconAnalyzer) calculateJitter(intervals []time.Duration, mean time.Duration) float64 {
	if len(intervals) < 2 || mean == 0 {
		return 0
	}

	var totalJitter float64
	for i := 1; i < len(intervals); i++ {
		diff := math.Abs(float64(intervals[i] - intervals[i-1]))
		totalJitter += diff
	}

	avgJitter := totalJitter / float64(len(intervals)-1)
	return (avgJitter / float64(mean)) * 100
}

// calculateBeaconScore calculates the overall beacon likelihood score
func (b *BeaconAnalyzer) calculateBeaconScore(mean time.Duration, stdDev, cov, jitter float64, count int, timing *models.ConnectionTiming) float64 {
	score := 0.0

	// Low coefficient of variation = regular intervals = likely beacon
	// CoV < 0.1: Very regular timing (strong beacon indicator)
	// CoV 0.1-0.2: Regular with minor variation
	// CoV 0.2-0.3: Typical C2 with jitter
	// CoV > 0.3: Likely human or random traffic
	if cov < 0.05 {
		score += 45 // Extremely regular - almost certainly automated
	} else if cov < 0.1 {
		score += 40 // Very regular
	} else if cov < 0.2 {
		score += 30 // Regular with minor jitter
	} else if cov < 0.3 {
		score += 20 // Typical C2 jitter range
	} else if cov < 0.5 {
		score += 10 // Some regularity
	}

	// Jitter analysis (C2 tools often have configurable jitter)
	// Low jitter with regular mean = strong indicator
	if jitter < 10 && cov < 0.2 {
		score += 15
	} else if jitter < 20 && cov < 0.3 {
		score += 10
	}

	// Connection frequency bonus
	// More connections = more confidence in pattern
	if count > 50 {
		score += 15
	} else if count > 30 {
		score += 10
	} else if count > 20 {
		score += 5
	}

	// Consistent payload sizes indicate automated behavior
	if timing != nil && len(timing.BytesSent) > 5 {
		bytesStdDev := b.calculateStdDevInt64(timing.BytesSent)
		bytesMean := b.calculateMeanInt64(timing.BytesSent)
		if bytesMean > 0 {
			bytesCov := bytesStdDev / float64(bytesMean)
			if bytesCov < 0.1 {
				score += 15 // Very consistent payload sizes
			} else if bytesCov < 0.3 {
				score += 10
			}
		}
	}

	// Interval in typical C2 range (5 seconds to 10 minutes)
	if mean >= 5*time.Second && mean <= 10*time.Minute {
		score += 5
	}

	return score
}

// matchC2Framework checks if timing matches known C2 frameworks
func (b *BeaconAnalyzer) matchC2Framework(mean time.Duration, cov, jitter float64, port int) (string, float64) {
	bestMatch := ""
	bestScore := 0.0

	for _, framework := range models.KnownC2Frameworks {
		matchScore := 0.0

		// Check interval range
		if mean >= framework.MinInterval && mean <= framework.MaxInterval {
			matchScore += 10
		}

		// Check jitter range
		jitterDecimal := jitter / 100.0
		if jitterDecimal >= framework.JitterRange[0] && jitterDecimal <= framework.JitterRange[1] {
			matchScore += 15
		}

		// Check port
		for _, typicalPort := range framework.TypicalPorts {
			if port == typicalPort {
				matchScore += 5
				break
			}
		}

		if matchScore > bestScore {
			bestScore = matchScore
			bestMatch = framework.Name
		}
	}

	if bestScore >= 20 {
		return bestMatch, bestScore
	}

	return "", 0
}

// detectPatternType identifies the type of beacon pattern
func (b *BeaconAnalyzer) detectPatternType(intervals []time.Duration, cov, jitter float64) string {
	if cov < 0.05 {
		return "fixed" // Almost no variation
	}

	if cov < 0.2 && jitter < 30 {
		return "jitter" // Regular with intentional jitter
	}

	// Check for exponential backoff pattern
	if b.isExponentialPattern(intervals) {
		return "exponential"
	}

	if cov > 0.5 {
		return "random" // High variation, likely not a beacon
	}

	return "unknown"
}

// isExponentialPattern detects exponential backoff patterns
func (b *BeaconAnalyzer) isExponentialPattern(intervals []time.Duration) bool {
	if len(intervals) < 5 {
		return false
	}

	// Check if intervals are increasing exponentially
	increasing := 0
	for i := 1; i < len(intervals); i++ {
		ratio := float64(intervals[i]) / float64(intervals[i-1])
		if ratio >= 1.5 && ratio <= 3.0 {
			increasing++
		}
	}

	// If more than 60% of intervals show exponential growth
	return float64(increasing)/float64(len(intervals)-1) > 0.6
}

// isWhitelisted checks if a destination is whitelisted
func (b *BeaconAnalyzer) isWhitelisted(ip string) bool {
	// Direct match
	if b.whitelist[ip] {
		return true
	}

	// Check wildcard patterns
	for pattern := range b.whitelist {
		if matchesWildcard(pattern, ip) {
			return true
		}
	}

	return false
}

// matchesWildcard checks if ip matches a wildcard pattern like "*.microsoft.com"
func matchesWildcard(pattern, target string) bool {
	if len(pattern) == 0 {
		return false
	}

	// Simple wildcard: *.example.com
	if pattern[0] == '*' && len(pattern) > 1 {
		suffix := pattern[1:] // e.g., ".microsoft.com"
		if len(target) > len(suffix) {
			return target[len(target)-len(suffix):] == suffix
		}
	}

	return pattern == target
}

// GetBeaconAnalysis returns the current beacon analysis results
func (b *BeaconAnalyzer) GetBeaconAnalysis() map[string]*models.BeaconAnalysis {
	b.mu.RLock()
	defer b.mu.RUnlock()

	result := make(map[string]*models.BeaconAnalysis)
	for k, v := range b.beaconAnalysis {
		result[k] = v
	}
	return result
}

// GetDetectedBeacons returns only connections flagged as likely beacons
func (b *BeaconAnalyzer) GetDetectedBeacons() []*models.BeaconAnalysis {
	b.mu.RLock()
	defer b.mu.RUnlock()

	var beacons []*models.BeaconAnalysis
	for _, analysis := range b.beaconAnalysis {
		if analysis.IsBeaconLikely {
			beacons = append(beacons, analysis)
		}
	}

	// Sort by score
	sort.Slice(beacons, func(i, j int) bool {
		return beacons[i].BeaconScore > beacons[j].BeaconScore
	})

	return beacons
}

// Cleanup removes old timing data for connections no longer active
func (b *BeaconAnalyzer) Cleanup(activeKeys map[string]bool, maxAge time.Duration) {
	b.mu.Lock()
	defer b.mu.Unlock()

	now := time.Now()

	for key, analysis := range b.beaconAnalysis {
		// Remove if not active and analysis is old
		if !activeKeys[key] && now.Sub(analysis.LastAnalyzed) > maxAge {
			delete(b.beaconAnalysis, key)
			delete(b.timingData, key)
		}
	}
}

// Helper functions for int64 slices

func (b *BeaconAnalyzer) calculateMeanInt64(values []int64) int64 {
	if len(values) == 0 {
		return 0
	}

	var total int64
	for _, v := range values {
		total += v
	}

	return total / int64(len(values))
}

func (b *BeaconAnalyzer) calculateStdDevInt64(values []int64) float64 {
	if len(values) == 0 {
		return 0
	}

	mean := float64(b.calculateMeanInt64(values))
	var sumSquares float64

	for _, v := range values {
		diff := float64(v) - mean
		sumSquares += diff * diff
	}

	variance := sumSquares / float64(len(values))
	return math.Sqrt(variance)
}
