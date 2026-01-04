package detonation

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/afterdarksys/afterdark-darkd/internal/models"
	"go.uber.org/zap"
)

// SandboxType defines the type of sandbox to use
type SandboxType string

const (
	SandboxTypeDocker SandboxType = "docker"
	SandboxTypeNative SandboxType = "native"
)

// Sandbox provides isolated execution environment for malware analysis
type Sandbox struct {
	sandboxType SandboxType
	dockerImage string
	timeout     time.Duration
	logger      *zap.Logger
	workDir     string
}

// SandboxConfig holds sandbox configuration
type SandboxConfig struct {
	Type        SandboxType
	DockerImage string
	Timeout     time.Duration
	WorkDir     string
}

// NewSandbox creates a new sandbox executor
func NewSandbox(cfg SandboxConfig, logger *zap.Logger) (*Sandbox, error) {
	if cfg.Type == SandboxTypeDocker {
		// Verify Docker is available
		if err := exec.Command("docker", "version").Run(); err != nil {
			return nil, fmt.Errorf("docker not available: %w", err)
		}
	}

	return &Sandbox{
		sandboxType: cfg.Type,
		dockerImage: cfg.DockerImage,
		timeout:     cfg.Timeout,
		logger:      logger,
		workDir:     cfg.WorkDir,
	}, nil
}

// DetonationResult holds the results of sandbox execution
type DetonationResult struct {
	ExitCode        int
	Stdout          string
	Stderr          string
	Duration        time.Duration
	NetworkCapture  []byte
	FileChanges     []FileChange
	ProcessTree     []ProcessEvent
	RegistryChanges []RegistryChange
	DNSQueries      []string
	HTTPRequests    []HTTPCapture
	Error           error
}

// FileChange represents a file system modification
type FileChange struct {
	Operation string    `json:"operation"` // create, modify, delete
	Path      string    `json:"path"`
	Size      int64     `json:"size,omitempty"`
	Hash      string    `json:"hash,omitempty"`
	Timestamp time.Time `json:"timestamp"`
}

// ProcessEvent represents a process creation/termination
type ProcessEvent struct {
	Operation   string    `json:"operation"` // create, terminate
	PID         int       `json:"pid"`
	PPID        int       `json:"ppid"`
	Name        string    `json:"name"`
	CommandLine string    `json:"command_line"`
	Timestamp   time.Time `json:"timestamp"`
}

// RegistryChange represents a registry modification (Windows)
type RegistryChange struct {
	Operation string    `json:"operation"` // create, modify, delete
	Key       string    `json:"key"`
	Value     string    `json:"value,omitempty"`
	Data      string    `json:"data,omitempty"`
	Timestamp time.Time `json:"timestamp"`
}

// HTTPCapture represents a captured HTTP request
type HTTPCapture struct {
	Method      string            `json:"method"`
	URL         string            `json:"url"`
	Headers     map[string]string `json:"headers,omitempty"`
	Body        string            `json:"body,omitempty"`
	StatusCode  int               `json:"status_code,omitempty"`
	Timestamp   time.Time         `json:"timestamp"`
}

// Detonate executes a sample in the sandbox and captures behavior
func (s *Sandbox) Detonate(ctx context.Context, sample *models.DetonationSample) (*DetonationResult, error) {
	switch s.sandboxType {
	case SandboxTypeDocker:
		return s.detonateDocker(ctx, sample)
	case SandboxTypeNative:
		return s.detonateNative(ctx, sample)
	default:
		return nil, fmt.Errorf("unsupported sandbox type: %s", s.sandboxType)
	}
}

// detonateDocker executes sample in isolated Docker container
func (s *Sandbox) detonateDocker(ctx context.Context, sample *models.DetonationSample) (*DetonationResult, error) {
	start := time.Now()
	result := &DetonationResult{}

	// Create temporary working directory
	workDir, err := os.MkdirTemp(s.workDir, "detonation-*")
	if err != nil {
		return nil, fmt.Errorf("failed to create work dir: %w", err)
	}
	defer os.RemoveAll(workDir)

	// Copy sample to work directory
	sampleDst := filepath.Join(workDir, "sample"+filepath.Ext(sample.FilePath))
	if err := copyFile(sample.FilePath, sampleDst); err != nil {
		return nil, fmt.Errorf("failed to copy sample: %w", err)
	}

	// Create output directories
	outputDir := filepath.Join(workDir, "output")
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create output dir: %w", err)
	}

	// Prepare Docker command with security restrictions
	containerName := fmt.Sprintf("detonation-%s", sample.ID[:8])

	args := []string{
		"run",
		"--rm",
		"--name", containerName,
		// Security: no network by default (can enable for specific analysis)
		"--network", "none",
		// Security: read-only root filesystem
		"--read-only",
		// Security: drop all capabilities
		"--cap-drop", "ALL",
		// Security: no new privileges
		"--security-opt", "no-new-privileges",
		// Resource limits
		"--memory", "512m",
		"--cpus", "1",
		"--pids-limit", "100",
		// Timeout
		"--stop-timeout", "10",
		// Mount sample and output directories
		"-v", fmt.Sprintf("%s:/sample:ro", workDir),
		"-v", fmt.Sprintf("%s:/output:rw", outputDir),
		// Environment for detonation script
		"-e", fmt.Sprintf("SAMPLE_FILE=/sample/%s", filepath.Base(sampleDst)),
		"-e", "OUTPUT_DIR=/output",
		// Use our detonation image
		s.dockerImage,
	}

	// Create context with timeout
	ctx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()

	// Run Docker container
	cmd := exec.CommandContext(ctx, "docker", args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	s.logger.Info("starting detonation",
		zap.String("sample_id", sample.ID),
		zap.String("container", containerName),
		zap.String("image", s.dockerImage),
	)

	err = cmd.Run()
	result.Duration = time.Since(start)
	result.Stdout = stdout.String()
	result.Stderr = stderr.String()

	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			result.Error = fmt.Errorf("detonation timed out after %v", s.timeout)
			// Kill container if still running
			exec.Command("docker", "kill", containerName).Run()
		} else if exitErr, ok := err.(*exec.ExitError); ok {
			result.ExitCode = exitErr.ExitCode()
		} else {
			result.Error = err
		}
	}

	// Parse output from detonation container
	if err := s.parseDetonationOutput(outputDir, result); err != nil {
		s.logger.Warn("failed to parse detonation output", zap.Error(err))
	}

	s.logger.Info("detonation completed",
		zap.String("sample_id", sample.ID),
		zap.Duration("duration", result.Duration),
		zap.Int("exit_code", result.ExitCode),
	)

	return result, nil
}

// detonateNative executes sample with system-level monitoring (more dangerous)
func (s *Sandbox) detonateNative(ctx context.Context, sample *models.DetonationSample) (*DetonationResult, error) {
	// Native detonation is platform-specific and requires elevated privileges
	// This is a simplified implementation for non-Docker environments

	start := time.Now()
	result := &DetonationResult{}

	s.logger.Warn("native detonation mode - limited isolation",
		zap.String("sample_id", sample.ID),
	)

	// For native mode, we only do static analysis
	// Actual execution would require platform-specific sandboxing
	result.Duration = time.Since(start)
	result.Error = fmt.Errorf("native detonation not fully implemented - use docker mode")

	return result, nil
}

// parseDetonationOutput reads results from the container output directory
func (s *Sandbox) parseDetonationOutput(outputDir string, result *DetonationResult) error {
	// Parse file changes
	fileChangesPath := filepath.Join(outputDir, "file_changes.json")
	if data, err := os.ReadFile(fileChangesPath); err == nil {
		var changes []FileChange
		if err := json.Unmarshal(data, &changes); err == nil {
			result.FileChanges = changes
		}
	}

	// Parse process tree
	processTreePath := filepath.Join(outputDir, "process_tree.json")
	if data, err := os.ReadFile(processTreePath); err == nil {
		var processes []ProcessEvent
		if err := json.Unmarshal(data, &processes); err == nil {
			result.ProcessTree = processes
		}
	}

	// Parse registry changes
	registryPath := filepath.Join(outputDir, "registry_changes.json")
	if data, err := os.ReadFile(registryPath); err == nil {
		var changes []RegistryChange
		if err := json.Unmarshal(data, &changes); err == nil {
			result.RegistryChanges = changes
		}
	}

	// Parse DNS queries
	dnsPath := filepath.Join(outputDir, "dns_queries.json")
	if data, err := os.ReadFile(dnsPath); err == nil {
		var queries []string
		if err := json.Unmarshal(data, &queries); err == nil {
			result.DNSQueries = queries
		}
	}

	// Parse HTTP requests
	httpPath := filepath.Join(outputDir, "http_requests.json")
	if data, err := os.ReadFile(httpPath); err == nil {
		var requests []HTTPCapture
		if err := json.Unmarshal(data, &requests); err == nil {
			result.HTTPRequests = requests
		}
	}

	// Read network capture if available
	pcapPath := filepath.Join(outputDir, "network.pcap")
	if data, err := os.ReadFile(pcapPath); err == nil {
		result.NetworkCapture = data
	}

	return nil
}

// IsDockerAvailable checks if Docker is available for sandboxing
func IsDockerAvailable() bool {
	cmd := exec.Command("docker", "info")
	return cmd.Run() == nil
}

// PullDetonationImage pulls the detonation container image
func (s *Sandbox) PullDetonationImage(ctx context.Context) error {
	s.logger.Info("pulling detonation image", zap.String("image", s.dockerImage))

	cmd := exec.CommandContext(ctx, "docker", "pull", s.dockerImage)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to pull image: %w: %s", err, string(output))
	}

	return nil
}

// copyFile copies a file from src to dst
func copyFile(src, dst string) error {
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return os.WriteFile(dst, data, 0644)
}

// ConvertToReport converts sandbox results to a DetonationReport
func ConvertToReport(sample *models.DetonationSample, result *DetonationResult, staticAnalysis *models.StaticAnalysis) *models.DetonationReport {
	report := &models.DetonationReport{
		SampleID:       sample.ID,
		Duration:       result.Duration,
		SandboxType:    "docker",
		StaticAnalysis: staticAnalysis,
		GeneratedAt:    time.Now(),
	}

	// Convert dynamic analysis
	report.DynamicAnalysis = &models.DynamicAnalysis{
		ExitCode:        result.ExitCode,
		Runtime:         result.Duration.Seconds(),
		CrashedOrHung:   result.ExitCode != 0,
		BehaviorSummary: generateBehaviorSummary(result),
	}

	// Convert network activity
	if len(result.DNSQueries) > 0 || len(result.HTTPRequests) > 0 {
		report.NetworkActivity = &models.NetworkActivity{}

		for _, query := range result.DNSQueries {
			report.NetworkActivity.DNSQueries = append(report.NetworkActivity.DNSQueries, models.DNSQuery{
				Query:     query,
				Timestamp: time.Now(),
			})
			report.NetworkActivity.ContactedDomains = append(report.NetworkActivity.ContactedDomains, query)
		}

		for _, req := range result.HTTPRequests {
			report.NetworkActivity.HTTPRequests = append(report.NetworkActivity.HTTPRequests, models.HTTPRequest{
				Method:    req.Method,
				URL:       req.URL,
				Headers:   req.Headers,
				Response:  req.StatusCode,
				Timestamp: req.Timestamp,
			})
		}
	}

	// Convert file activity
	if len(result.FileChanges) > 0 {
		report.FileActivity = &models.FileActivity{}
		for _, change := range result.FileChanges {
			switch change.Operation {
			case "create":
				report.FileActivity.FilesCreated = append(report.FileActivity.FilesCreated, models.FileOp{
					Path:      change.Path,
					Size:      change.Size,
					Timestamp: change.Timestamp,
				})
			case "modify":
				report.FileActivity.FilesModified = append(report.FileActivity.FilesModified, models.FileOp{
					Path:      change.Path,
					Size:      change.Size,
					Timestamp: change.Timestamp,
				})
			case "delete":
				report.FileActivity.FilesDeleted = append(report.FileActivity.FilesDeleted, change.Path)
			}
		}
	}

	// Convert registry activity
	if len(result.RegistryChanges) > 0 {
		report.RegistryActivity = &models.RegistryActivity{}
		for _, change := range result.RegistryChanges {
			regOp := models.RegistryOp{
				Key:       change.Key,
				Value:     change.Value,
				Data:      change.Data,
				Timestamp: change.Timestamp,
			}
			switch change.Operation {
			case "create":
				report.RegistryActivity.KeysCreated = append(report.RegistryActivity.KeysCreated, regOp)
				// Check for autorun
				if isAutorunKey(change.Key) {
					report.RegistryActivity.AutorunEntries = append(report.RegistryActivity.AutorunEntries, regOp)
				}
			case "modify":
				report.RegistryActivity.KeysModified = append(report.RegistryActivity.KeysModified, regOp)
			case "delete":
				report.RegistryActivity.KeysDeleted = append(report.RegistryActivity.KeysDeleted, change.Key)
			}
		}
	}

	// Convert process activity
	if len(result.ProcessTree) > 0 {
		report.ProcessActivity = &models.ProcessActivity{}
		for _, proc := range result.ProcessTree {
			if proc.Operation == "create" {
				report.ProcessActivity.ProcessesCreated = append(report.ProcessActivity.ProcessesCreated, models.ProcessInfo{
					PID:         proc.PID,
					Name:        proc.Name,
					CommandLine: proc.CommandLine,
					ParentPID:   proc.PPID,
					Timestamp:   proc.Timestamp,
				})
				if proc.CommandLine != "" {
					report.ProcessActivity.CommandLines = append(report.ProcessActivity.CommandLines, proc.CommandLine)
				}
			}
		}
	}

	// Calculate threat score
	report.ThreatScore = calculateThreatScore(report)
	report.Confidence = 0.8 // Base confidence for sandbox analysis

	// Extract IOCs
	report.IOCs = extractIOCs(report)

	return report
}

func generateBehaviorSummary(result *DetonationResult) string {
	var summary []string

	if len(result.FileChanges) > 0 {
		summary = append(summary, fmt.Sprintf("Modified %d files", len(result.FileChanges)))
	}
	if len(result.RegistryChanges) > 0 {
		summary = append(summary, fmt.Sprintf("Modified %d registry keys", len(result.RegistryChanges)))
	}
	if len(result.ProcessTree) > 0 {
		summary = append(summary, fmt.Sprintf("Created %d processes", len(result.ProcessTree)))
	}
	if len(result.DNSQueries) > 0 {
		summary = append(summary, fmt.Sprintf("Made %d DNS queries", len(result.DNSQueries)))
	}
	if len(result.HTTPRequests) > 0 {
		summary = append(summary, fmt.Sprintf("Made %d HTTP requests", len(result.HTTPRequests)))
	}

	if len(summary) == 0 {
		return "No significant behavior detected"
	}

	return strings.Join(summary, "; ")
}

func isAutorunKey(key string) bool {
	autorunPaths := []string{
		"CurrentVersion\\Run",
		"CurrentVersion\\RunOnce",
		"CurrentVersion\\RunServices",
		"CurrentVersion\\Policies\\Explorer\\Run",
	}
	for _, path := range autorunPaths {
		if strings.Contains(strings.ToLower(key), strings.ToLower(path)) {
			return true
		}
	}
	return false
}

func calculateThreatScore(report *models.DetonationReport) int {
	score := 0

	// Static analysis factors
	if report.StaticAnalysis != nil {
		if report.StaticAnalysis.IsPacked {
			score += 15
		}
		if report.StaticAnalysis.IsEncrypted {
			score += 20
		}
		if report.StaticAnalysis.Entropy > 7.5 {
			score += 10
		}
		score += len(report.StaticAnalysis.Strings) / 5 // Suspicious strings
	}

	// Dynamic analysis factors
	if report.DynamicAnalysis != nil {
		if report.DynamicAnalysis.DetectedEvasion {
			score += 25
		}
	}

	// Network activity
	if report.NetworkActivity != nil {
		score += len(report.NetworkActivity.ContactedDomains) * 5
		score += len(report.NetworkActivity.HTTPRequests) * 3
	}

	// File activity
	if report.FileActivity != nil {
		score += len(report.FileActivity.DroppedFiles) * 10
		score += len(report.FileActivity.FilesCreated) * 2
	}

	// Registry activity (Windows)
	if report.RegistryActivity != nil {
		score += len(report.RegistryActivity.AutorunEntries) * 20
		score += len(report.RegistryActivity.KeysCreated) * 2
	}

	// Process activity
	if report.ProcessActivity != nil {
		score += len(report.ProcessActivity.ProcessesInjected) * 30
		score += len(report.ProcessActivity.ProcessesCreated) * 5
	}

	// Cap at 100
	if score > 100 {
		score = 100
	}

	return score
}

func extractIOCs(report *models.DetonationReport) []models.IOC {
	var iocs []models.IOC

	// Extract network IOCs
	if report.NetworkActivity != nil {
		for _, domain := range report.NetworkActivity.ContactedDomains {
			iocs = append(iocs, models.IOC{
				Type:       "domain",
				Value:      domain,
				Context:    "DNS query during execution",
				Confidence: 80,
			})
		}
		for _, ip := range report.NetworkActivity.ContactedIPs {
			iocs = append(iocs, models.IOC{
				Type:       "ip",
				Value:      ip,
				Context:    "Network connection during execution",
				Confidence: 80,
			})
		}
		for _, req := range report.NetworkActivity.HTTPRequests {
			iocs = append(iocs, models.IOC{
				Type:       "url",
				Value:      req.URL,
				Context:    fmt.Sprintf("HTTP %s request during execution", req.Method),
				Confidence: 85,
			})
		}
	}

	// Extract file IOCs
	if report.FileActivity != nil {
		for _, file := range report.FileActivity.DroppedFiles {
			iocs = append(iocs, models.IOC{
				Type:       "hash",
				Value:      file.Hashes.SHA256,
				Context:    fmt.Sprintf("Dropped file: %s", file.Path),
				Confidence: 90,
			})
		}
	}

	// Extract registry IOCs
	if report.RegistryActivity != nil {
		for _, entry := range report.RegistryActivity.AutorunEntries {
			iocs = append(iocs, models.IOC{
				Type:       "registry",
				Value:      entry.Key,
				Context:    "Autorun persistence mechanism",
				Confidence: 95,
			})
		}
	}

	return iocs
}
