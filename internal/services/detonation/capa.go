package detonation

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"go.uber.org/zap"
)

// CAPAExecutor runs CAPA (FLARE Capability Analysis) against malware samples
type CAPAExecutor struct {
	capaPath   string
	rulesDir   string
	workDir    string
	log        *zap.Logger
}

// CAPAConfig holds CAPA executor configuration
type CAPAConfig struct {
	CAPAPath string // Path to CAPA executable
	RulesDir string // Path to CAPA rules directory
	WorkDir  string // Working directory for analysis
}

// NewCAPAExecutor creates a new CAPA executor
func NewCAPAExecutor(cfg CAPAConfig, log *zap.Logger) (*CAPAExecutor, error) {
	// Check if CAPA is installed
	capaPath := cfg.CAPAPath
	if capaPath == "" {
		// Try to find capa in PATH
		path, err := exec.LookPath("capa")
		if err != nil {
			return nil, fmt.Errorf("capa not found in PATH and no path specified: %w", err)
		}
		capaPath = path
	}

	// Verify CAPA executable exists
	if _, err := os.Stat(capaPath); err != nil {
		return nil, fmt.Errorf("capa executable not found at %s: %w", capaPath, err)
	}

	// Check rules directory
	if cfg.RulesDir != "" {
		if _, err := os.Stat(cfg.RulesDir); err != nil {
			return nil, fmt.Errorf("rules directory not found at %s: %w", cfg.RulesDir, err)
		}
	}

	return &CAPAExecutor{
		capaPath: capaPath,
		rulesDir: cfg.RulesDir,
		workDir:  cfg.WorkDir,
		log:      log,
	}, nil
}

// CAPAResult represents the output from CAPA analysis
type CAPAResult struct {
	Path         string              `json:"path"`
	MD5          string              `json:"md5"`
	SHA1         string              `json:"sha1"`
	SHA256       string              `json:"sha256"`
	Rules        CAPARules           `json:"rules"`
	Capabilities map[string]CAPACapabilityResult `json:"capabilities"`
	Metadata     CAPAMetadata        `json:"meta"`
	Success      bool                `json:"success"`
	Error        string              `json:"error,omitempty"`
	Duration     time.Duration       `json:"duration"`
}

// CAPARules holds CAPA rules metadata
type CAPARules struct {
	Path    string `json:"path"`
	Count   int    `json:"count"`
	Version string `json:"version,omitempty"`
}

// CAPACapabilityResult represents a detected capability
type CAPACapabilityResult struct {
	Meta    CAPACapabilityMeta `json:"meta"`
	Matches []CAPAMatch        `json:"matches"`
}

// CAPACapabilityMeta holds capability metadata
type CAPACapabilityMeta struct {
	Name       string   `json:"name"`
	Namespace  string   `json:"namespace"`
	Scope      string   `json:"scope"`
	MBC        []string `json:"mbc,omitempty"`
	ATTCK      []string `json:"att&ck,omitempty"`
	References []string `json:"references,omitempty"`
	Examples   []string `json:"examples,omitempty"`
}

// CAPAMatch represents where a capability was found
type CAPAMatch struct {
	Success  bool                   `json:"success"`
	Node     map[string]interface{} `json:"node"`
	Children []CAPAMatch            `json:"children,omitempty"`
	Locations []CAPALocation        `json:"locations,omitempty"`
}

// CAPALocation represents a code location where capability was detected
type CAPALocation struct {
	Type  string                 `json:"type"`
	Value interface{}            `json:"value"`
}

// CAPAMetadata holds analysis metadata
type CAPAMetadata struct {
	Timestamp   time.Time          `json:"timestamp"`
	Version     string             `json:"version"`
	Argv        []string           `json:"argv,omitempty"`
	Sample      CAPASampleMetadata `json:"sample"`
	Analysis    CAPAAnalysisMeta   `json:"analysis"`
}

// CAPASampleMetadata holds sample file metadata
type CAPASampleMetadata struct {
	MD5    string `json:"md5"`
	SHA1   string `json:"sha1"`
	SHA256 string `json:"sha256"`
	Path   string `json:"path"`
}

// CAPAAnalysisMeta holds analysis configuration metadata
type CAPAAnalysisMeta struct {
	Format      string `json:"format"`
	Arch        string `json:"arch"`
	OS          string `json:"os"`
	Extractor   string `json:"extractor"`
	Rules       string `json:"rules"`
	BaseAddress string `json:"base_address,omitempty"`
	Layout      map[string]interface{} `json:"layout,omitempty"`
	FeatureCounts map[string]int `json:"feature_counts,omitempty"`
}

// Analyze runs CAPA analysis on a file
func (c *CAPAExecutor) Analyze(filePath string) (*CAPAResult, error) {
	startTime := time.Now()

	// Build command
	args := []string{filePath, "-j"} // -j for JSON output

	if c.rulesDir != "" {
		args = append(args, "-r", c.rulesDir)
	}

	c.log.Info("Running CAPA analysis",
		zap.String("file", filePath),
		zap.String("capa_path", c.capaPath),
		zap.String("rules_dir", c.rulesDir),
	)

	cmd := exec.Command(c.capaPath, args...)
	cmd.Dir = c.workDir

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	duration := time.Since(startTime)

	if err != nil {
		c.log.Error("CAPA analysis failed",
			zap.String("file", filePath),
			zap.Error(err),
			zap.String("stderr", stderr.String()),
		)

		return &CAPAResult{
			Path:     filePath,
			Success:  false,
			Error:    fmt.Sprintf("CAPA execution failed: %v - %s", err, stderr.String()),
			Duration: duration,
		}, err
	}

	// Parse JSON output
	var result CAPAResult
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
		return &CAPAResult{
			Path:     filePath,
			Success:  false,
			Error:    fmt.Sprintf("failed to parse CAPA output: %v", err),
			Duration: duration,
		}, err
	}

	result.Path = filePath
	result.Success = true
	result.Duration = duration

	c.log.Info("CAPA analysis completed",
		zap.String("file", filePath),
		zap.Int("capabilities", len(result.Capabilities)),
		zap.Duration("duration", duration),
	)

	return &result, nil
}

// GetCapabilities extracts a simplified list of detected capabilities
func (c *CAPAExecutor) GetCapabilities(result *CAPAResult) []string {
	capabilities := make([]string, 0, len(result.Capabilities))
	for name := range result.Capabilities {
		capabilities = append(capabilities, name)
	}
	return capabilities
}

// GetMBC extracts MITRE ATT&CK for Mobile Behavior Catalog mappings
func (c *CAPAExecutor) GetMBC(result *CAPAResult) []string {
	mbcSet := make(map[string]bool)
	for _, cap := range result.Capabilities {
		for _, mbc := range cap.Meta.MBC {
			mbcSet[mbc] = true
		}
	}

	mbc := make([]string, 0, len(mbcSet))
	for m := range mbcSet {
		mbc = append(mbc, m)
	}
	return mbc
}

// GetATTCK extracts MITRE ATT&CK mappings
func (c *CAPAExecutor) GetATTCK(result *CAPAResult) []string {
	attckSet := make(map[string]bool)
	for _, cap := range result.Capabilities {
		for _, attck := range cap.Meta.ATTCK {
			attckSet[attck] = true
		}
	}

	attck := make([]string, 0, len(attckSet))
	for a := range attckSet {
		attck = append(attck, a)
	}
	return attck
}

// CalculateThreatScore calculates a threat score based on detected capabilities
func (c *CAPAExecutor) CalculateThreatScore(result *CAPAResult) float64 {
	if !result.Success {
		return 0.0
	}

	baseScore := float64(len(result.Capabilities)) * 2.0

	// Weight by dangerous namespaces
	for capName, cap := range result.Capabilities {
		namespace := cap.Meta.Namespace

		switch {
		case contains(namespace, "anti-analysis"):
			baseScore += 15.0
		case contains(namespace, "persistence"):
			baseScore += 12.0
		case contains(namespace, "defense-evasion"):
			baseScore += 10.0
		case contains(namespace, "collection"):
			baseScore += 8.0
		case contains(namespace, "command-and-control"):
			baseScore += 10.0
		case contains(namespace, "exfiltration"):
			baseScore += 12.0
		case contains(namespace, "impact"):
			baseScore += 15.0
		case contains(capName, "ransomware"):
			baseScore += 25.0
		case contains(capName, "keylog"):
			baseScore += 15.0
		case contains(capName, "backdoor"):
			baseScore += 20.0
		}
	}

	// Cap at 100
	if baseScore > 100 {
		baseScore = 100
	}

	return baseScore
}

// ExportToFile exports CAPA results to a JSON file
func (c *CAPAExecutor) ExportToFile(result *CAPAResult, outputPath string) error {
	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal result: %w", err)
	}

	if err := os.MkdirAll(filepath.Dir(outputPath), 0755); err != nil {
		return fmt.Errorf("failed to create output directory: %w", err)
	}

	if err := os.WriteFile(outputPath, data, 0644); err != nil {
		return fmt.Errorf("failed to write output file: %w", err)
	}

	c.log.Info("CAPA results exported",
		zap.String("output", outputPath),
	)

	return nil
}

// contains checks if a string contains a substring (case-insensitive)
func contains(s, substr string) bool {
	return bytes.Contains([]byte(s), []byte(substr))
}

// UpdateRules updates CAPA rules from the official repository
func (c *CAPAExecutor) UpdateRules() error {
	if c.rulesDir == "" {
		return fmt.Errorf("no rules directory configured")
	}

	c.log.Info("Updating CAPA rules",
		zap.String("rules_dir", c.rulesDir),
	)

	// CAPA can update its own rules
	cmd := exec.Command(c.capaPath, "update-rules")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to update rules: %w", err)
	}

	c.log.Info("CAPA rules updated successfully")
	return nil
}
