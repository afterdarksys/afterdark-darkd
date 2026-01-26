package memscan

import (
	"os"
	"path/filepath"
	"testing"

	"go.uber.org/zap"
)

func TestYARAScannerCreation(t *testing.T) {
	logger := zap.NewNop()

	// Test with empty rules dir
	scanner, err := NewYARAScanner("", logger)
	if err != nil {
		t.Fatalf("unexpected error with empty rules dir: %v", err)
	}
	if scanner == nil {
		t.Fatal("expected non-nil scanner")
	}
	if scanner.GetLoadedRules() != 0 {
		t.Errorf("expected 0 rules with empty dir, got %d", scanner.GetLoadedRules())
	}

	// Test with non-existent directory
	scanner, err = NewYARAScanner("/nonexistent/path", logger)
	if err != nil {
		t.Fatalf("unexpected error with non-existent dir: %v", err)
	}
	if scanner.GetLoadedRules() != 0 {
		t.Errorf("expected 0 rules with non-existent dir, got %d", scanner.GetLoadedRules())
	}
}

func TestYARARuleLoading(t *testing.T) {
	// Create temp directory with test rules
	tempDir, err := os.MkdirTemp("", "yara-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Create a test YARA rule file
	testRule := `
rule TestMalware {
    meta:
        description = "Test rule for malware detection"
        author = "Test"
        severity = "high"
    strings:
        $str1 = "malicious_string"
        $str2 = { 4D 5A 90 00 }
    condition:
        any of them
}

rule AnotherRule {
    meta:
        description = "Another test rule"
    strings:
        $hex = { DE AD BE EF }
    condition:
        $hex
}
`
	rulePath := filepath.Join(tempDir, "test_rules.yar")
	if err := os.WriteFile(rulePath, []byte(testRule), 0644); err != nil {
		t.Fatalf("failed to write test rule: %v", err)
	}

	logger := zap.NewNop()
	scanner, err := NewYARAScanner(tempDir, logger)
	if err != nil {
		t.Fatalf("failed to create scanner: %v", err)
	}

	if scanner.GetLoadedRules() != 2 {
		t.Errorf("expected 2 rules, got %d", scanner.GetLoadedRules())
	}

	names := scanner.GetRuleNames()
	if len(names) != 2 {
		t.Errorf("expected 2 rule names, got %d", len(names))
	}
}

func TestYARAScanning(t *testing.T) {
	// Create temp directory with test rules
	tempDir, err := os.MkdirTemp("", "yara-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Create rule that matches specific strings
	testRule := `
rule TestPattern {
    meta:
        description = "Test pattern match"
    strings:
        $pattern = "INFECTED"
    condition:
        $pattern
}

rule HexPattern {
    meta:
        description = "Hex pattern match"
    strings:
        $hex = { CA FE BA BE }
    condition:
        $hex
}
`
	rulePath := filepath.Join(tempDir, "patterns.yara")
	if err := os.WriteFile(rulePath, []byte(testRule), 0644); err != nil {
		t.Fatalf("failed to write test rule: %v", err)
	}

	logger := zap.NewNop()
	scanner, err := NewYARAScanner(tempDir, logger)
	if err != nil {
		t.Fatalf("failed to create scanner: %v", err)
	}

	tests := []struct {
		name          string
		data          []byte
		expectedMatch bool
		expectedRule  string
	}{
		{
			name:          "match string pattern",
			data:          []byte("This file is INFECTED with malware"),
			expectedMatch: true,
			expectedRule:  "TestPattern",
		},
		{
			name:          "match hex pattern",
			data:          []byte{0x00, 0x00, 0xCA, 0xFE, 0xBA, 0xBE, 0x00, 0x00},
			expectedMatch: true,
			expectedRule:  "HexPattern",
		},
		{
			name:          "no match",
			data:          []byte("This is a clean file with no suspicious content"),
			expectedMatch: false,
			expectedRule:  "",
		},
		{
			name:          "empty data",
			data:          []byte{},
			expectedMatch: false,
			expectedRule:  "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matches := scanner.Scan(tt.data, 0x1000)

			if tt.expectedMatch && len(matches) == 0 {
				t.Error("expected match but got none")
			}

			if !tt.expectedMatch && len(matches) > 0 {
				t.Errorf("unexpected match: %+v", matches)
			}

			if tt.expectedMatch && len(matches) > 0 {
				found := false
				for _, m := range matches {
					if m.Rule == tt.expectedRule {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("expected rule %q not found in matches", tt.expectedRule)
				}
			}
		})
	}
}

func TestParseHexString(t *testing.T) {
	logger := zap.NewNop()
	scanner, _ := NewYARAScanner("", logger)

	tests := []struct {
		name     string
		input    string
		expected []byte
	}{
		{
			name:     "simple hex",
			input:    "{ 41 42 43 44 }",
			expected: []byte{0x41, 0x42, 0x43, 0x44},
		},
		{
			name:     "no spaces",
			input:    "{DEADBEEF}",
			expected: []byte{0xDE, 0xAD, 0xBE, 0xEF},
		},
		{
			name:     "with wildcards",
			input:    "{ 41 ?? 43 }",
			expected: []byte{0x41, 0x00, 0x43}, // Wildcards become 0
		},
		{
			name:     "lowercase",
			input:    "{ de ad be ef }",
			expected: []byte{0xde, 0xad, 0xbe, 0xef},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := scanner.parseHexString(tt.input)
			if len(result) != len(tt.expected) {
				t.Errorf("expected length %d, got %d", len(tt.expected), len(result))
				return
			}
			for i, b := range result {
				if b != tt.expected[i] {
					t.Errorf("byte %d: expected 0x%02X, got 0x%02X", i, tt.expected[i], b)
				}
			}
		})
	}
}

func TestParseMetaSection(t *testing.T) {
	logger := zap.NewNop()
	scanner, _ := NewYARAScanner("", logger)

	metaSection := `
        description = "Test malware rule"
        author = "Security Team"
        severity = "high"
        date = "2024-01-15"
    `

	meta := scanner.parseMeta(metaSection)

	expected := map[string]string{
		"description": "Test malware rule",
		"author":      "Security Team",
		"severity":    "high",
		"date":        "2024-01-15",
	}

	for key, expectedVal := range expected {
		if val, ok := meta[key]; !ok || val != expectedVal {
			t.Errorf("meta[%q]: expected %q, got %q", key, expectedVal, val)
		}
	}
}

func TestBytesToHex(t *testing.T) {
	logger := zap.NewNop()
	scanner, _ := NewYARAScanner("", logger)

	tests := []struct {
		input    []byte
		expected string
	}{
		{[]byte{0xDE, 0xAD, 0xBE, 0xEF}, "DEADBEEF"},
		{[]byte{0x00, 0xFF}, "00FF"},
		{[]byte{0x41, 0x42, 0x43}, "414243"},
		{[]byte{}, ""},
	}

	for _, tt := range tests {
		result := scanner.bytesToHex(tt.input)
		if result != tt.expected {
			t.Errorf("bytesToHex(%v): expected %q, got %q", tt.input, tt.expected, result)
		}
	}
}

func TestPatternMatching(t *testing.T) {
	logger := zap.NewNop()
	scanner, _ := NewYARAScanner("", logger)

	tests := []struct {
		name    string
		data    []byte
		pattern []byte
		isHex   bool
		match   bool
	}{
		{
			name:    "exact match",
			data:    []byte{0x41, 0x42, 0x43, 0x44},
			pattern: []byte{0x41, 0x42, 0x43, 0x44},
			isHex:   false,
			match:   true,
		},
		{
			name:    "no match",
			data:    []byte{0x41, 0x42, 0x43, 0x44},
			pattern: []byte{0x45, 0x46, 0x47, 0x48},
			isHex:   false,
			match:   false,
		},
		{
			name:    "hex with wildcard",
			data:    []byte{0x41, 0xFF, 0x43},
			pattern: []byte{0x41, 0x00, 0x43}, // 0x00 is wildcard for hex
			isHex:   true,
			match:   true,
		},
		{
			name:    "length mismatch",
			data:    []byte{0x41, 0x42},
			pattern: []byte{0x41, 0x42, 0x43},
			isHex:   false,
			match:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := scanner.matchPattern(tt.data, tt.pattern, tt.isHex)
			if result != tt.match {
				t.Errorf("expected match=%v, got %v", tt.match, result)
			}
		})
	}
}
