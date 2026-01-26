package memscan

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/afterdarksys/afterdark-darkd/internal/models"
	"go.uber.org/zap"
)

// YARAScanner handles YARA rule scanning
// Note: Full implementation requires CGO with libyara
// This is a simplified implementation that can be extended
type YARAScanner struct {
	logger    *zap.Logger
	rulesDir  string
	rules     []YARARule
	compiled  bool
}

// YARARule represents a loaded YARA rule
type YARARule struct {
	Name      string
	Namespace string
	Strings   []YARARuleString
	Condition string
	Meta      map[string]string
}

// YARARuleString represents a string in a YARA rule
type YARARuleString struct {
	Identifier string
	Value      []byte
	IsHex      bool
	IsRegex    bool
}

// NewYARAScanner creates a new YARA scanner
func NewYARAScanner(rulesDir string, logger *zap.Logger) (*YARAScanner, error) {
	scanner := &YARAScanner{
		logger:   logger.Named("yara"),
		rulesDir: rulesDir,
		rules:    make([]YARARule, 0),
	}

	if err := scanner.loadRules(); err != nil {
		return nil, err
	}

	return scanner, nil
}

// loadRules loads YARA rules from the rules directory
func (s *YARAScanner) loadRules() error {
	if s.rulesDir == "" {
		return nil
	}

	// Check if directory exists
	if _, err := os.Stat(s.rulesDir); os.IsNotExist(err) {
		s.logger.Warn("YARA rules directory does not exist", zap.String("path", s.rulesDir))
		return nil
	}

	// Load all .yar and .yara files
	err := filepath.Walk(s.rulesDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil // Skip errors
		}

		if info.IsDir() {
			return nil
		}

		ext := strings.ToLower(filepath.Ext(path))
		if ext != ".yar" && ext != ".yara" {
			return nil
		}

		if err := s.loadRuleFile(path); err != nil {
			s.logger.Warn("failed to load YARA rule file",
				zap.String("path", path),
				zap.Error(err))
		}

		return nil
	})

	if err != nil {
		return err
	}

	s.compiled = true
	s.logger.Info("YARA rules loaded", zap.Int("count", len(s.rules)))

	return nil
}

// loadRuleFile loads rules from a single file
// Note: This is a simplified parser - production should use libyara
func (s *YARAScanner) loadRuleFile(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	// Extract namespace from filename
	namespace := strings.TrimSuffix(filepath.Base(path), filepath.Ext(path))

	// Simple rule extraction (not a full YARA parser)
	content := string(data)
	ruleStarts := strings.Split(content, "rule ")

	for i, rulePart := range ruleStarts {
		if i == 0 || len(rulePart) < 10 {
			continue
		}

		// Extract rule name
		nameEnd := strings.IndexAny(rulePart, " :{")
		if nameEnd < 0 {
			continue
		}

		ruleName := strings.TrimSpace(rulePart[:nameEnd])
		if ruleName == "" {
			continue
		}

		rule := YARARule{
			Name:      ruleName,
			Namespace: namespace,
			Meta:      make(map[string]string),
		}

		// Extract meta section
		if metaStart := strings.Index(rulePart, "meta:"); metaStart >= 0 {
			metaEnd := strings.Index(rulePart[metaStart:], "strings:")
			if metaEnd < 0 {
				metaEnd = strings.Index(rulePart[metaStart:], "condition:")
			}
			if metaEnd > 0 {
				metaSection := rulePart[metaStart+5 : metaStart+metaEnd]
				rule.Meta = s.parseMeta(metaSection)
			}
		}

		// Extract strings section
		if stringsStart := strings.Index(rulePart, "strings:"); stringsStart >= 0 {
			stringsEnd := strings.Index(rulePart[stringsStart:], "condition:")
			if stringsEnd > 0 {
				stringsSection := rulePart[stringsStart+8 : stringsStart+stringsEnd]
				rule.Strings = s.parseStrings(stringsSection)
			}
		}

		s.rules = append(s.rules, rule)
	}

	return nil
}

// parseMeta parses the meta section of a rule
func (s *YARAScanner) parseMeta(section string) map[string]string {
	meta := make(map[string]string)

	lines := strings.Split(section, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		parts := strings.SplitN(line, "=", 2)
		if len(parts) == 2 {
			key := strings.TrimSpace(parts[0])
			value := strings.Trim(strings.TrimSpace(parts[1]), "\"")
			meta[key] = value
		}
	}

	return meta
}

// parseStrings parses the strings section of a rule
func (s *YARAScanner) parseStrings(section string) []YARARuleString {
	var strings_ []YARARuleString

	lines := strings.Split(section, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || !strings.HasPrefix(line, "$") {
			continue
		}

		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}

		identifier := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])

		ruleString := YARARuleString{
			Identifier: identifier,
		}

		// Detect string type
		if strings.HasPrefix(value, "{") && strings.HasSuffix(value, "}") {
			// Hex string
			ruleString.IsHex = true
			ruleString.Value = s.parseHexString(value)
		} else if strings.HasPrefix(value, "/") {
			// Regex
			ruleString.IsRegex = true
			ruleString.Value = []byte(strings.Trim(value, "/"))
		} else {
			// Plain string
			ruleString.Value = []byte(strings.Trim(value, "\""))
		}

		strings_ = append(strings_, ruleString)
	}

	return strings_
}

// parseHexString parses a YARA hex string
func (s *YARAScanner) parseHexString(hex string) []byte {
	// Remove braces and whitespace
	hex = strings.Trim(hex, "{}")
	hex = strings.ReplaceAll(hex, " ", "")

	var result []byte
	for i := 0; i+1 < len(hex); i += 2 {
		if hex[i] == '?' {
			result = append(result, 0) // Wildcard
			continue
		}

		var b byte
		for j := 0; j < 2; j++ {
			b <<= 4
			c := hex[i+j]
			switch {
			case c >= '0' && c <= '9':
				b |= c - '0'
			case c >= 'a' && c <= 'f':
				b |= c - 'a' + 10
			case c >= 'A' && c <= 'F':
				b |= c - 'A' + 10
			}
		}
		result = append(result, b)
	}

	return result
}

// Scan scans data against loaded YARA rules
func (s *YARAScanner) Scan(data []byte, baseAddress uint64) []models.YARAMatch {
	if !s.compiled || len(s.rules) == 0 {
		return nil
	}

	var matches []models.YARAMatch

	for _, rule := range s.rules {
		if ruleMatches := s.matchRule(rule, data, baseAddress); len(ruleMatches) > 0 {
			match := models.YARAMatch{
				Rule:      rule.Name,
				Namespace: rule.Namespace,
				Strings:   ruleMatches,
				Meta:      rule.Meta,
				Address:   baseAddress,
			}
			matches = append(matches, match)
		}
	}

	return matches
}

// matchRule checks if a rule matches the data
func (s *YARAScanner) matchRule(rule YARARule, data []byte, baseAddress uint64) []models.YARAString {
	var matchedStrings []models.YARAString

	for _, ruleStr := range rule.Strings {
		if ruleStr.IsRegex {
			// Skip regex for simplified implementation
			continue
		}

		// Find all occurrences
		pattern := ruleStr.Value
		for i := 0; i <= len(data)-len(pattern); i++ {
			if s.matchPattern(data[i:i+len(pattern)], pattern, ruleStr.IsHex) {
				matchedStrings = append(matchedStrings, models.YARAString{
					Name:   ruleStr.Identifier,
					Offset: baseAddress + uint64(i),
					Data:   s.bytesToHex(data[i : i+len(pattern)]),
					Length: len(pattern),
				})
			}
		}
	}

	return matchedStrings
}

// matchPattern matches a pattern against data
func (s *YARAScanner) matchPattern(data, pattern []byte, isHex bool) bool {
	if len(data) != len(pattern) {
		return false
	}

	for i := range pattern {
		if isHex && pattern[i] == 0 {
			// Wildcard in hex pattern
			continue
		}
		if data[i] != pattern[i] {
			return false
		}
	}

	return true
}

// bytesToHex converts bytes to hex string
func (s *YARAScanner) bytesToHex(data []byte) string {
	const hexChars = "0123456789ABCDEF"
	result := make([]byte, len(data)*2)
	for i, b := range data {
		result[i*2] = hexChars[b>>4]
		result[i*2+1] = hexChars[b&0x0f]
	}
	return string(result)
}

// GetLoadedRules returns the number of loaded rules
func (s *YARAScanner) GetLoadedRules() int {
	return len(s.rules)
}

// GetRuleNames returns names of all loaded rules
func (s *YARAScanner) GetRuleNames() []string {
	names := make([]string, len(s.rules))
	for i, rule := range s.rules {
		names[i] = rule.Namespace + ":" + rule.Name
	}
	return names
}
