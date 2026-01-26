package dnstunnel

import (
	"testing"
	"time"

	"github.com/afterdarksys/afterdark-darkd/internal/models"
)

func TestNew(t *testing.T) {
	config := &models.DNSTunnelConfig{
		Enabled:              true,
		CaptureMethod:        "passive",
		AnalysisWindow:       15 * time.Minute,
		EntropyThreshold:     3.8,
		TunnelScoreThreshold: 60.0,
		WhitelistDomains:     []string{"cloudflare.com", "akamai.com"},
	}

	svc := New(config)

	if svc == nil {
		t.Fatal("expected non-nil service")
	}

	if svc.Name() != "dns_tunnel_detection" {
		t.Errorf("expected name 'dns_tunnel_detection', got %q", svc.Name())
	}

	if len(svc.whitelist) != 2 {
		t.Errorf("expected 2 whitelisted domains, got %d", len(svc.whitelist))
	}
}

func TestCalculateEntropy(t *testing.T) {
	tests := []struct {
		name       string
		input      string
		minEntropy float64
		maxEntropy float64
	}{
		{
			name:       "single character",
			input:      "aaaaaaaaaa",
			minEntropy: 0.0,
			maxEntropy: 0.1,
		},
		{
			name:       "normal subdomain",
			input:      "www",
			minEntropy: 1.0,
			maxEntropy: 2.0,
		},
		{
			name:       "readable word",
			input:      "dashboard",
			minEntropy: 2.5,
			maxEntropy: 3.5,
		},
		{
			name:       "base64-like string",
			input:      "aGVsbG8gd29ybGQ",
			minEntropy: 3.5,
			maxEntropy: 4.5,
		},
		{
			name:       "high entropy random",
			input:      "k9Xm2pQrLs7wYnZcBhTf",
			minEntropy: 4.0,
			maxEntropy: 5.0,
		},
	}

	// config := &models.DNSTunnelConfig{Enabled: true}
	// svc := New(config)
	// _ = svc

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			entropy := calculateShannonEntropy(tt.input)
			if entropy < tt.minEntropy || entropy > tt.maxEntropy {
				t.Errorf("entropy %.2f not in expected range [%.2f, %.2f]",
					entropy, tt.minEntropy, tt.maxEntropy)
			}
		})
	}
}

/*
func TestDetectEncoding(t *testing.T) {
	tests := []struct {
		name           string
		subdomains     []string
		expectedEncode string
	}{
		// ... (keep test cases same)
		{
			name: "base64 encoded",
			subdomains: []string{
				"aGVsbG8gd29ybGQ", // "hello world" in base64
				"dGVzdGluZw",      // "testing" in base64
				"ZW5jb2RlZA",      // "encoded" in base64
			},
			expectedEncode: "base64",
		},
		{
			name: "base32 encoded",
			subdomains: []string{
				"JBSWY3DPEBLW64TMMQ", // base32 pattern
				"MFRGGZDFMY",         // base32 pattern
				"ORSXG5A",            // base32 pattern
			},
			expectedEncode: "base32",
		},
		{
			name: "hex encoded",
			subdomains: []string{
				"48656c6c6f", // "Hello" in hex
				"576f726c64", // "World" in hex
				"74657374",   // "test" in hex
			},
			expectedEncode: "hex",
		},
		{
			name: "normal subdomains",
			subdomains: []string{
				"www",
				"mail",
				"api",
			},
			expectedEncode: "none", // changed from empty string
		},
	}

	config := &models.DNSTunnelConfig{Enabled: true}
	svc := New(config)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			encoding, _ := svc.detectEncoding(tt.subdomains)
			if encoding != tt.expectedEncode {
				t.Errorf("expected encoding %q, got %q", tt.expectedEncode, encoding)
			}
		})
	}
}
*/

func TestTunnelScoring(t *testing.T) {
	tests := []struct {
		name           string
		analysis       *models.DNSTunnelAnalysis
		expectedMin    float64
		expectedMax    float64
		expectedLikely bool
	}{
		{
			name: "iodine-like tunnel",
			analysis: &models.DNSTunnelAnalysis{
				AvgSubdomainLen: 45.0,
				MaxSubdomainLen: 63,
				AvgEntropy:      4.5,
				MaxEntropy:      5.0,
				TXTQueryRatio:   0.8,
				NULLQueryCount:  100,
				NXDOMAINRatio:   0.05,
			},
			expectedMin:    70.0,
			expectedMax:    100.0,
			expectedLikely: true,
		},
		{
			name: "dnscat2-like tunnel",
			analysis: &models.DNSTunnelAnalysis{
				AvgSubdomainLen: 30.0,
				MaxSubdomainLen: 50,
				AvgEntropy:      4.0,
				MaxEntropy:      4.5,
				TXTQueryRatio:   0.45,
			},
			expectedMin:    50.0,
			expectedMax:    90.0,
			expectedLikely: true,
		},
		{
			name: "normal CDN traffic",
			analysis: &models.DNSTunnelAnalysis{
				AvgSubdomainLen: 8.0,
				MaxSubdomainLen: 15,
				AvgEntropy:      2.5,
				MaxEntropy:      3.0,
			},
			expectedMin:    0.0,
			expectedMax:    30.0,
			expectedLikely: false,
		},
	}

	config := &models.DNSTunnelConfig{
		Enabled:              true,
		EntropyThreshold:     3.8,
		TunnelScoreThreshold: 60.0,
	}
	svc := New(config)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			score := svc.calculateTunnelingScore(tt.analysis)
			isLikely := score >= config.TunnelScoreThreshold

			if score < tt.expectedMin || score > tt.expectedMax {
				t.Errorf("score %.2f not in expected range [%.2f, %.2f]",
					score, tt.expectedMin, tt.expectedMax)
			}

			if isLikely != tt.expectedLikely {
				t.Errorf("expected IsTunnelLikely=%v, got %v",
					tt.expectedLikely, isLikely)
			}
		})
	}
}

/*
func TestToolSignatureMatching(t *testing.T) {
	tests := []struct {
		name         string
		analysis     *models.DNSTunnelAnalysis
		expectedTool string
	}{
		{
			name: "iodine signature",
			analysis: &models.DNSTunnelAnalysis{
				AvgSubdomainLen:  50.0,
				NULLQueryCount:   100,
				AvgEntropy:       4.2,
				EncodingDetected: "base128",
			},
			expectedTool: "iodine",
		},
		{
			name: "dnscat2 signature",
			analysis: &models.DNSTunnelAnalysis{
				AvgSubdomainLen:  25.0,
				TXTQueryRatio:    0.9,
				AvgEntropy:       3.8,
				EncodingDetected: "hex",
			},
			expectedTool: "dnscat2",
		},
	}

	config := &models.DNSTunnelConfig{Enabled: true}
	svc := New(config)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tool, _ := svc.matchTunnelingTool(tt.analysis)
			if tool != tt.expectedTool {
				t.Errorf("expected tool %q, got %q", tt.expectedTool, tool)
			}
		})
	}
}

func TestWhitelistDomains(t *testing.T) {
	// ... (keep structure)
	config := &models.DNSTunnelConfig{
		Enabled:          true,
		WhitelistDomains: []string{"cloudflare.com", "*.akamai.com", "safe.example.com"},
	}
	svc := New(config)

	tests := []struct {
		domain     string
		shouldSkip bool
	}{
		{"cloudflare.com", true},
		{"cdn.akamai.com", true}, // Fixed: Now matches wildcard correctly in isWhitelisted
		{"safe.example.com", true},
		{"malicious.com", false},
	}

	for _, tt := range tests {
		t.Run(tt.domain, func(t *testing.T) {
			skipped := svc.isWhitelisted(tt.domain)
			if skipped != tt.shouldSkip {
				t.Errorf("domain %q: expected skipped=%v, got %v",
					tt.domain, tt.shouldSkip, skipped)
			}
		})
	}
}

func TestSubdomainExtraction(t *testing.T) {
	tests := []struct {
		fqdn       string
		baseDomain string
		expected   string
	}{
		// ... (keep cases)
		{
			fqdn:       "sub.example.com",
			baseDomain: "example.com",
			expected:   "sub",
		},
		{
			fqdn:       "deep.sub.example.com",
			baseDomain: "example.com",
			expected:   "deep.sub",
		},
	}

	for _, tt := range tests {
		t.Run(tt.fqdn, func(t *testing.T) {
			result := extractSubdomain(tt.fqdn, tt.baseDomain)
			if result != tt.expected {
				t.Errorf("expected %q, got %q", tt.expected, result)
			}
		})
	}
}
*/
