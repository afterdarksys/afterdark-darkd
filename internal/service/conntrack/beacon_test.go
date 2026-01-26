package conntrack

import (
	"testing"
	"time"

	"github.com/afterdarksys/afterdark-darkd/internal/models"
	"go.uber.org/zap"
)

func TestNewBeaconAnalyzer(t *testing.T) {
	config := &models.C2DetectionConfig{
		Enabled:               true,
		MinConnections:        10,
		AnalysisWindow:        time.Hour,
		BeaconThreshold:       60.0,
		KnownGoodDestinations: []string{"*.microsoft.com", "*.apple.com"},
	}

	logger := zap.NewNop()
	analyzer := NewBeaconAnalyzer(config, logger)

	if analyzer == nil {
		t.Fatal("expected non-nil analyzer")
	}

	if analyzer.config != config {
		t.Error("config not set correctly")
	}

	if len(analyzer.whitelist) != 2 {
		t.Errorf("expected 2 whitelisted destinations, got %d", len(analyzer.whitelist))
	}
}

func TestRecordConnection(t *testing.T) {
	config := &models.C2DetectionConfig{
		Enabled:        true,
		MinConnections: 5,
		BeaconThreshold: 60.0,
	}

	logger := zap.NewNop()
	analyzer := NewBeaconAnalyzer(config, logger)

	conn := &models.NetworkConnection{
		LocalAddr:  "192.168.1.100",
		LocalPort:  52000,
		RemoteAddr: "10.0.0.50",
		RemotePort: 443,
	}

	// Record multiple connections
	for i := 0; i < 10; i++ {
		analyzer.RecordConnection("test-key", conn, 100, 200)
		time.Sleep(10 * time.Millisecond)
	}

	analyzer.mu.RLock()
	timing, exists := analyzer.timingData["test-key"]
	analyzer.mu.RUnlock()

	if !exists {
		t.Fatal("timing data should exist")
	}

	if timing.GetIntervalCount() < 9 {
		t.Errorf("expected at least 9 intervals, got %d", timing.GetIntervalCount())
	}
}

func TestBeaconScoreCalculation(t *testing.T) {
	tests := []struct {
		name           string
		intervals      []time.Duration
		expectedScore  float64
		expectedLikely bool
		pattern        string
	}{
		{
			name: "fixed interval - high beacon score",
			intervals: []time.Duration{
				60 * time.Second, 60 * time.Second, 60 * time.Second,
				60 * time.Second, 60 * time.Second, 60 * time.Second,
				60 * time.Second, 60 * time.Second, 60 * time.Second,
				60 * time.Second,
			},
			expectedScore:  70.0, // Should be high due to low CoV
			expectedLikely: true,
			pattern:        "fixed",
		},
		{
			name: "jitter pattern - moderate beacon score",
			intervals: []time.Duration{
				58 * time.Second, 62 * time.Second, 59 * time.Second,
				61 * time.Second, 60 * time.Second, 58 * time.Second,
				63 * time.Second, 57 * time.Second, 61 * time.Second,
				59 * time.Second,
			},
			expectedScore:  50.0, // Moderate due to jitter
			expectedLikely: false,
			pattern:        "jitter",
		},
		{
			name: "random intervals - low beacon score",
			intervals: []time.Duration{
				10 * time.Second, 120 * time.Second, 5 * time.Second,
				300 * time.Second, 45 * time.Second, 180 * time.Second,
				15 * time.Second, 90 * time.Second, 200 * time.Second,
				30 * time.Second,
			},
			expectedScore:  20.0, // Low due to high variance
			expectedLikely: false,
			pattern:        "random",
		},
	}

	config := &models.C2DetectionConfig{
		Enabled:         true,
		MinConnections:  5,
		BeaconThreshold: 60.0,
	}
	logger := zap.NewNop()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			analyzer := NewBeaconAnalyzer(config, logger)

			// Create timing data from intervals
			timing := &models.ConnectionTiming{}
			baseTime := time.Now().Add(-time.Duration(len(tt.intervals)) * time.Minute)

			for i, interval := range tt.intervals {
				ts := baseTime.Add(time.Duration(i) * interval)
				timing.AddTimestamp(ts, 100, 200)
			}

			// Create tracked connection
			tracked := &models.TrackedConnection{
				FirstSeen: baseTime,
				LastSeen:  time.Now(),
			}

			// Set timing data
			analyzer.mu.Lock()
			analyzer.timingData["test-key"] = timing
			analyzer.mu.Unlock()

			// Run analysis
			results := analyzer.AnalyzeBeacons(map[string]*models.TrackedConnection{
				"test-key": tracked,
			})

			if len(results) == 0 && tt.expectedLikely {
				t.Error("expected beacon to be detected")
			}

			if len(results) > 0 {
				result := results[0]
				if result.IsBeaconLikely != tt.expectedLikely {
					t.Errorf("expected IsBeaconLikely=%v, got %v", tt.expectedLikely, result.IsBeaconLikely)
				}

				// Allow some variance in score
				scoreDiff := result.BeaconScore - tt.expectedScore
				if scoreDiff < -30 || scoreDiff > 30 {
					t.Errorf("expected score around %.0f, got %.0f", tt.expectedScore, result.BeaconScore)
				}
			}
		})
	}
}

func TestC2FrameworkMatching(t *testing.T) {
	tests := []struct {
		name             string
		meanInterval     time.Duration
		jitterPercent    float64
		expectedFramework string
	}{
		{
			name:             "Cobalt Strike default",
			meanInterval:     60 * time.Second,
			jitterPercent:    10.0,
			expectedFramework: "cobalt_strike",
		},
		{
			name:             "Metasploit default",
			meanInterval:     5 * time.Second,
			jitterPercent:    5.0,
			expectedFramework: "metasploit",
		},
		{
			name:             "Sliver default",
			meanInterval:     30 * time.Second,
			jitterPercent:    15.0,
			expectedFramework: "sliver",
		},
		{
			name:             "No match - unusual interval",
			meanInterval:     7 * time.Minute,
			jitterPercent:    50.0,
			expectedFramework: "",
		},
	}

	config := &models.C2DetectionConfig{
		Enabled:         true,
		MinConnections:  5,
		BeaconThreshold: 60.0,
	}
	logger := zap.NewNop()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			analyzer := NewBeaconAnalyzer(config, logger)

			framework := analyzer.matchC2Framework(tt.meanInterval, tt.jitterPercent)

			if framework != tt.expectedFramework {
				t.Errorf("expected framework %q, got %q", tt.expectedFramework, framework)
			}
		})
	}
}

func TestWhitelistFiltering(t *testing.T) {
	config := &models.C2DetectionConfig{
		Enabled:               true,
		MinConnections:        5,
		BeaconThreshold:       60.0,
		KnownGoodDestinations: []string{"10.0.0.1", "trusted.example.com"},
	}

	logger := zap.NewNop()
	analyzer := NewBeaconAnalyzer(config, logger)

	// Whitelisted connection
	whitelistedConn := &models.NetworkConnection{
		LocalAddr:  "192.168.1.100",
		RemoteAddr: "10.0.0.1",
		RemotePort: 443,
	}

	// Record connections (should be ignored)
	for i := 0; i < 10; i++ {
		analyzer.RecordConnection("whitelisted-key", whitelistedConn, 100, 200)
	}

	analyzer.mu.RLock()
	_, exists := analyzer.timingData["whitelisted-key"]
	analyzer.mu.RUnlock()

	if exists {
		t.Error("whitelisted connection should not be recorded")
	}

	// Non-whitelisted connection
	normalConn := &models.NetworkConnection{
		LocalAddr:  "192.168.1.100",
		RemoteAddr: "suspicious.example.com",
		RemotePort: 443,
	}

	for i := 0; i < 10; i++ {
		analyzer.RecordConnection("normal-key", normalConn, 100, 200)
	}

	analyzer.mu.RLock()
	_, exists = analyzer.timingData["normal-key"]
	analyzer.mu.RUnlock()

	if !exists {
		t.Error("non-whitelisted connection should be recorded")
	}
}

func TestPatternDetection(t *testing.T) {
	config := &models.C2DetectionConfig{
		Enabled:         true,
		MinConnections:  5,
		BeaconThreshold: 60.0,
	}
	logger := zap.NewNop()
	analyzer := NewBeaconAnalyzer(config, logger)

	tests := []struct {
		name           string
		coeffVariation float64
		expectedPattern string
	}{
		{
			name:           "very low variance - fixed",
			coeffVariation: 0.05,
			expectedPattern: "fixed",
		},
		{
			name:           "moderate variance - jitter",
			coeffVariation: 0.15,
			expectedPattern: "jitter",
		},
		{
			name:           "high variance - exponential",
			coeffVariation: 0.40,
			expectedPattern: "exponential",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pattern := analyzer.detectPatternType(tt.coeffVariation)
			if pattern != tt.expectedPattern {
				t.Errorf("expected pattern %q, got %q", tt.expectedPattern, pattern)
			}
		})
	}
}
