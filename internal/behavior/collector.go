// Package behavior provides client-side behavior profiling and snapshot collection
// for integration with AfterDark Security Server.
package behavior

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"runtime"
	"time"

	"github.com/afterdarksys/afterdark-darkd/internal/models"
	"github.com/shirou/gopsutil/v3/host"
	"github.com/shirou/gopsutil/v3/net"
	"github.com/shirou/gopsutil/v3/process"
)

// Collector gathers system behavioral data and submits to ADSS
type Collector struct {
	config     *models.Config
	httpClient *http.Client
	endpointID string
}

// SystemSnapshot represents the snapshot sent to behavior analytics server
type SystemSnapshot struct {
	EndpointID         string        `json:"endpoint_id"`
	Timestamp          time.Time     `json:"timestamp"`
	OSInfo             OSInfo        `json:"os_info"`
	InstalledPatches   []Patch       `json:"patches"`
	RunningProcesses   []Process     `json:"processes"`
	SuspiciousFiles    []FileIOC     `json:"suspicious_files"`
	NetworkConnections []NetworkIOC  `json:"network_connections"`
	RegistryKeys       []RegistryIOC `json:"registry_keys,omitempty"`
	Services           []Service     `json:"services"`
	Packages           []Package     `json:"packages"`
}

// OSInfo represents operating system information
type OSInfo struct {
	Type         string `json:"type"`
	Version      string `json:"version"`
	Build        string `json:"build,omitempty"`
	Kernel       string `json:"kernel,omitempty"`
	Architecture string `json:"architecture"`
	Hostname     string `json:"hostname"`
}

// Patch represents an installed system patch
type Patch struct {
	PatchID     string    `json:"patch_id"`
	KB          string    `json:"kb,omitempty"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	InstalledAt time.Time `json:"installed_at"`
	Version     string    `json:"version"`
	Category    string    `json:"category,omitempty"`
	Source      string    `json:"source,omitempty"`
}

// Process represents running process metadata
type Process struct {
	PID            int       `json:"pid"`
	Name           string    `json:"name"`
	Path           string    `json:"path"`
	CommandLine    string    `json:"command_line"`
	User           string    `json:"user"`
	ParentPID      int       `json:"parent_pid"`
	StartTime      time.Time `json:"start_time"`
	Hash           string    `json:"hash,omitempty"`
	Signed         bool      `json:"signed"`
	Signer         string    `json:"signer,omitempty"`
	NetworkConns   int       `json:"network_connections"`
	MemoryUsageMB  float64   `json:"memory_usage_mb,omitempty"`
	CPUPercent     float64   `json:"cpu_percent,omitempty"`
	OpenFiles      int       `json:"open_files,omitempty"`
	Suspicious     bool      `json:"suspicious,omitempty"`
	SuspiciousNote string    `json:"suspicious_note,omitempty"`
}

// FileIOC represents a file indicator of compromise
type FileIOC struct {
	Path           string            `json:"path"`
	Hash           string            `json:"hash"`
	MD5            string            `json:"md5,omitempty"`
	SHA1           string            `json:"sha1,omitempty"`
	Size           int64             `json:"size"`
	ModTime        time.Time         `json:"mod_time"`
	CreateTime     time.Time         `json:"create_time,omitempty"`
	Permissions    string            `json:"permissions"`
	Owner          string            `json:"owner"`
	Signed         bool              `json:"signed"`
	Signer         string            `json:"signer,omitempty"`
	Entropy        float64           `json:"entropy,omitempty"`
	MimeType       string            `json:"mime_type,omitempty"`
	IsPE           bool              `json:"is_pe,omitempty"`
	IsELF          bool              `json:"is_elf,omitempty"`
	IsMachO        bool              `json:"is_macho,omitempty"`
	Suspicious     bool              `json:"suspicious"`
	SuspiciousNote string            `json:"suspicious_note,omitempty"`
	Attributes     map[string]string `json:"attributes,omitempty"`
}

// NetworkIOC represents a network indicator of compromise
type NetworkIOC struct {
	Protocol       string    `json:"protocol"`
	LocalAddress   string    `json:"local_address"`
	LocalPort      int       `json:"local_port"`
	RemoteAddress  string    `json:"remote_address"`
	RemotePort     int       `json:"remote_port"`
	State          string    `json:"state"`
	ProcessPID     int       `json:"process_pid,omitempty"`
	ProcessName    string    `json:"process_name,omitempty"`
	BytesSent      int64     `json:"bytes_sent,omitempty"`
	BytesReceived  int64     `json:"bytes_received,omitempty"`
	FirstSeen      time.Time `json:"first_seen"`
	LastSeen       time.Time `json:"last_seen"`
	Suspicious     bool      `json:"suspicious"`
	SuspiciousNote string    `json:"suspicious_note,omitempty"`
	GeoLocation    string    `json:"geo_location,omitempty"`
	ASN            string    `json:"asn,omitempty"`
}

// RegistryIOC represents a Windows registry indicator of compromise
type RegistryIOC struct {
	Hive           string    `json:"hive"`
	Key            string    `json:"key"`
	ValueName      string    `json:"value_name"`
	ValueType      string    `json:"value_type"`
	Value          string    `json:"value"`
	ModTime        time.Time `json:"mod_time"`
	Suspicious     bool      `json:"suspicious"`
	SuspiciousNote string    `json:"suspicious_note,omitempty"`
}

// Service represents a system service
type Service struct {
	Name        string `json:"name"`
	DisplayName string `json:"display_name,omitempty"`
	Status      string `json:"status"`
	StartType   string `json:"start_type"`
	Path        string `json:"path"`
	User        string `json:"user,omitempty"`
	Description string `json:"description,omitempty"`
}

// Package represents an installed software package
type Package struct {
	Name         string    `json:"name"`
	Version      string    `json:"version"`
	Architecture string    `json:"architecture,omitempty"`
	Source       string    `json:"source"`
	InstalledAt  time.Time `json:"installed_at,omitempty"`
	Description  string    `json:"description,omitempty"`
	Vendor       string    `json:"vendor,omitempty"`
}

// NewCollector creates a new behavior collector
func NewCollector(config *models.Config, endpointID string) *Collector {
	return &Collector{
		config:     config,
		endpointID: endpointID,
		httpClient: &http.Client{
			Timeout: config.API.AfterDark.Timeout,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: false,
				},
			},
		},
	}
}

// CollectSnapshot gathers current system state
func (c *Collector) CollectSnapshot() (*SystemSnapshot, error) {
	snapshot := &SystemSnapshot{
		EndpointID: c.endpointID,
		Timestamp:  time.Now().UTC(),
	}

	// Collect OS information
	osInfo, err := c.collectOSInfo()
	if err == nil {
		snapshot.OSInfo = osInfo
	}

	// Collect running processes
	processes, err := c.collectProcesses()
	if err == nil {
		snapshot.RunningProcesses = processes
	}

	// Collect network connections
	networkConns, err := c.collectNetworkConnections()
	if err == nil {
		snapshot.NetworkConnections = networkConns
	}

	// Collect installed packages (OS-specific)
	packages, err := c.collectPackages()
	if err == nil {
		snapshot.Packages = packages
	}

	// Collect services
	services, err := c.collectServices()
	if err == nil {
		snapshot.Services = services
	}

	// Platform-specific collection
	if runtime.GOOS == "windows" {
		registryKeys, err := c.collectRegistryKeys()
		if err == nil {
			snapshot.RegistryKeys = registryKeys
		}
	}

	return snapshot, nil
}

// collectOSInfo gathers OS information
func (c *Collector) collectOSInfo() (OSInfo, error) {
	info, err := host.Info()
	if err != nil {
		return OSInfo{}, err
	}

	return OSInfo{
		Type:         info.OS,
		Version:      info.PlatformVersion,
		Build:        info.PlatformFamily,
		Kernel:       info.KernelVersion,
		Architecture: info.KernelArch,
		Hostname:     info.Hostname,
	}, nil
}

// collectProcesses gathers running process information
func (c *Collector) collectProcesses() ([]Process, error) {
	pids, err := process.Pids()
	if err != nil {
		return nil, err
	}

	var processes []Process
	for _, pid := range pids {
		p, err := process.NewProcess(pid)
		if err != nil {
			continue
		}

		name, _ := p.Name()
		exe, _ := p.Exe()
		cmdline, _ := p.Cmdline()
		username, _ := p.Username()
		ppid, _ := p.Ppid()
		createTime, _ := p.CreateTime()
		memInfo, _ := p.MemoryInfo()
		cpuPercent, _ := p.CPUPercent()
		numFDs, _ := p.NumFDs()

		proc := Process{
			PID:         int(pid),
			Name:        name,
			Path:        exe,
			CommandLine: cmdline,
			User:        username,
			ParentPID:   int(ppid),
			StartTime:   time.Unix(createTime/1000, 0),
		}

		if memInfo != nil {
			proc.MemoryUsageMB = float64(memInfo.RSS) / 1024 / 1024
		}
		proc.CPUPercent = cpuPercent
		proc.OpenFiles = int(numFDs)

		// Mark suspicious processes (basic heuristics)
		proc.Suspicious = c.isProcessSuspicious(proc)
		if proc.Suspicious {
			proc.SuspiciousNote = "Flagged by heuristic analysis"
		}

		processes = append(processes, proc)
	}

	return processes, nil
}

// collectNetworkConnections gathers network connection information
func (c *Collector) collectNetworkConnections() ([]NetworkIOC, error) {
	conns, err := net.Connections("all")
	if err != nil {
		return nil, err
	}

	var networkIOCs []NetworkIOC
	now := time.Now().UTC()

	for _, conn := range conns {
		var protocol string
		if conn.Type == 1 {
			protocol = "TCP"
		} else if conn.Type == 2 {
			protocol = "UDP"
		} else {
			protocol = fmt.Sprintf("TYPE_%d", conn.Type)
		}

		ioc := NetworkIOC{
			Protocol:      protocol,
			LocalAddress:  conn.Laddr.IP,
			LocalPort:     int(conn.Laddr.Port),
			RemoteAddress: conn.Raddr.IP,
			RemotePort:    int(conn.Raddr.Port),
			State:         conn.Status,
			ProcessPID:    int(conn.Pid),
			FirstSeen:     now,
			LastSeen:      now,
		}

		// Mark suspicious connections (basic heuristics)
		ioc.Suspicious = c.isConnectionSuspicious(ioc)
		if ioc.Suspicious {
			ioc.SuspiciousNote = "Flagged by heuristic analysis"
		}

		networkIOCs = append(networkIOCs, ioc)
	}

	return networkIOCs, nil
}

// collectPackages gathers installed package information
func (c *Collector) collectPackages() ([]Package, error) {
	// This is OS-specific and would need platform-specific implementations
	// For now, return empty list
	return []Package{}, nil
}

// collectServices gathers system service information
func (c *Collector) collectServices() ([]Service, error) {
	// This is OS-specific and would need platform-specific implementations
	// For now, return empty list
	return []Service{}, nil
}

// collectRegistryKeys gathers Windows registry keys (Windows only)
func (c *Collector) collectRegistryKeys() ([]RegistryIOC, error) {
	// Windows-specific implementation would go here
	return []RegistryIOC{}, nil
}

// isProcessSuspicious applies basic heuristics to flag suspicious processes
func (c *Collector) isProcessSuspicious(proc Process) bool {
	// Basic heuristics - extend as needed
	suspiciousNames := []string{
		"nc", "netcat", "ncat",
		"mimikatz",
		"psexec",
	}

	for _, name := range suspiciousNames {
		if proc.Name == name {
			return true
		}
	}

	// High CPU usage
	if proc.CPUPercent > 90.0 {
		return true
	}

	// Unsigned binaries in sensitive locations
	if !proc.Signed && (proc.Path == "/usr/bin" || proc.Path == "/bin") {
		return true
	}

	return false
}

// isConnectionSuspicious applies basic heuristics to flag suspicious connections
func (c *Collector) isConnectionSuspicious(conn NetworkIOC) bool {
	// Connections to common C2 ports
	suspiciousPorts := []int{4444, 5555, 6666, 7777, 8080, 8888, 9999}
	for _, port := range suspiciousPorts {
		if conn.RemotePort == port {
			return true
		}
	}

	// Connections to private IPs from public-facing processes
	// (simplified check)
	if conn.RemoteAddress == "0.0.0.0" || conn.RemoteAddress == "127.0.0.1" {
		return false
	}

	return false
}

// SubmitSnapshot submits the snapshot to the AfterDark Security Server
func (c *Collector) SubmitSnapshot(ctx context.Context, snapshot *SystemSnapshot) error {
	url := fmt.Sprintf("%s/api/v1/behavior/snapshot", c.config.API.AfterDark.URL)

	jsonData, err := json.Marshal(snapshot)
	if err != nil {
		return fmt.Errorf("failed to marshal snapshot: %w", err)
	}

	// Retry logic
	var lastErr error
	for attempt := 0; attempt <= c.config.API.AfterDark.Retry.MaxAttempts; attempt++ {
		if attempt > 0 {
			time.Sleep(c.config.API.AfterDark.Retry.InitialWait)
		}

		req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(jsonData))
		if err != nil {
			return fmt.Errorf("failed to create request: %w", err)
		}

		req.Header.Set("Content-Type", "application/json")
		if c.config.API.AfterDark.APIKey != "" {
			req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", c.config.API.AfterDark.APIKey))
		}

		resp, err := c.httpClient.Do(req)
		if err != nil {
			lastErr = err
			continue
		}

		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()

		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			return nil
		}

		if resp.StatusCode >= 500 {
			lastErr = fmt.Errorf("server error: %d", resp.StatusCode)
			continue
		}

		return fmt.Errorf("failed to submit snapshot: status %d", resp.StatusCode)
	}

	return fmt.Errorf("failed after %d attempts: %w", c.config.API.AfterDark.Retry.MaxAttempts, lastErr)
}

// GetRiskScore retrieves the current risk score for this endpoint
func (c *Collector) GetRiskScore(ctx context.Context) (*RiskScoreResponse, error) {
	url := fmt.Sprintf("%s/api/v1/behavior/risk-score/%s", c.config.API.AfterDark.URL, c.endpointID)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	if c.config.API.AfterDark.APIKey != "" {
		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", c.config.API.AfterDark.APIKey))
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to get risk score: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to get risk score: status %d", resp.StatusCode)
	}

	var riskScore RiskScoreResponse
	if err := json.NewDecoder(resp.Body).Decode(&riskScore); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return &riskScore, nil
}

// RiskScoreResponse represents the risk score response from the server
type RiskScoreResponse struct {
	EndpointID         string    `json:"endpoint_id"`
	RiskScore          float64   `json:"risk_score"`
	AnomalyScore       float64   `json:"anomaly_score"`
	VulnerabilityCount int       `json:"vulnerability_count"`
	CriticalCount      int       `json:"critical_count"`
	HighCount          int       `json:"high_count"`
	MediumCount        int       `json:"medium_count"`
	LowCount           int       `json:"low_count"`
	ExploitAvailable   bool      `json:"exploit_available"`
	LastUpdated        time.Time `json:"last_updated"`
}
