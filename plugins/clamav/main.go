// ClamAV Integration Plugin for afterdark-darkd
// Copyright (C) 2025 After Dark Systems, LLC
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.
//
// SPDX-License-Identifier: GPL-3.0-or-later
//
// This plugin provides integration with ClamAV antivirus engine for real-time
// malware detection and on-demand scanning. ClamAV (https://www.clamav.net/)
// is licensed under the GNU General Public License version 2 (GPLv2).
//
// Build: go build -o clamav-plugin .
// Install: cp clamav-plugin /var/lib/afterdark-darkd/plugins/

package main

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	sdk "github.com/afterdarksys/afterdark-darkd/pkg/pluginsdk"
)

const (
	// Default socket path for clamd
	defaultClamdSocket = "/var/run/clamav/clamd.sock"

	// Default timeout for scan operations
	defaultScanTimeout = 5 * time.Minute

	// Default freshclam database directory
	defaultDBDir = "/var/lib/clamav"

	// Scan result codes
	scanResultClean    = 0
	scanResultInfected = 1
	scanResultError    = 2
)

// ScanResult represents the result of a file or directory scan
type ScanResult struct {
	Path        string    `json:"path"`
	Status      string    `json:"status"` // "clean", "infected", "error"
	Threat      string    `json:"threat,omitempty"`
	Size        int64     `json:"size,omitempty"`
	ScannedAt   time.Time `json:"scanned_at"`
	Duration    string    `json:"duration"`
	ErrorMsg    string    `json:"error,omitempty"`
	IsDirectory bool      `json:"is_directory"`
}

// ScanSummary provides aggregate statistics for a scan
type ScanSummary struct {
	TotalFiles    int           `json:"total_files"`
	ScannedFiles  int           `json:"scanned_files"`
	InfectedFiles int           `json:"infected_files"`
	Errors        int           `json:"errors"`
	DataScanned   int64         `json:"data_scanned_bytes"`
	Duration      time.Duration `json:"duration"`
	Threats       []ScanResult  `json:"threats,omitempty"`
}

// DatabaseInfo contains ClamAV signature database information
type DatabaseInfo struct {
	Name        string    `json:"name"`
	Version     string    `json:"version"`
	Signatures  int64     `json:"signatures"`
	BuildTime   time.Time `json:"build_time"`
	LastUpdated time.Time `json:"last_updated"`
}

// ClamdStatus represents the clamd daemon status
type ClamdStatus struct {
	Running        bool           `json:"running"`
	Version        string         `json:"version"`
	DatabaseInfo   []DatabaseInfo `json:"database_info"`
	TotalSignatures int64         `json:"total_signatures"`
	SocketPath     string         `json:"socket_path"`
	Uptime         string         `json:"uptime,omitempty"`
	Threads        int            `json:"threads,omitempty"`
	Queue          int            `json:"queue,omitempty"`
}

// ClamAVPlugin implements the ServicePlugin interface for ClamAV integration
type ClamAVPlugin struct {
	sdk.BaseServicePlugin

	mu           sync.RWMutex
	socketPath   string
	scanTimeout  time.Duration
	dbDir        string
	conn         net.Conn
	version      string
	logger       func(string, ...interface{})

	// Statistics
	scansCompleted  int64
	threatsDetected int64
	lastScanTime    time.Time
	errorCount      int64
}

func (c *ClamAVPlugin) Info() sdk.PluginInfo {
	return sdk.PluginInfo{
		Name:        "clamav",
		Version:     "1.0.0",
		Type:        sdk.PluginTypeService,
		Description: "ClamAV antivirus integration for malware detection and scanning",
		Author:      "After Dark Systems, LLC",
		License:     "GPL-3.0-or-later",
		Capabilities: []string{
			"scan_file",
			"scan_directory",
			"scan_stream",
			"update_database",
			"get_status",
			"get_version",
			"reload_database",
			"real_time_protection",
		},
	}
}

func (c *ClamAVPlugin) Configure(config map[string]interface{}) error {
	if err := c.BaseServicePlugin.Configure(config); err != nil {
		return err
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	// Set socket path
	c.socketPath = defaultClamdSocket
	if path, ok := config["socket_path"].(string); ok && path != "" {
		c.socketPath = path
	}

	// Set scan timeout
	c.scanTimeout = defaultScanTimeout
	if timeout, ok := config["scan_timeout"].(int); ok && timeout > 0 {
		c.scanTimeout = time.Duration(timeout) * time.Second
	}

	// Set database directory
	c.dbDir = defaultDBDir
	if dir, ok := config["db_dir"].(string); ok && dir != "" {
		c.dbDir = dir
	}

	// Default logger
	c.logger = func(format string, args ...interface{}) {
		fmt.Printf("[clamav] "+format+"\n", args...)
	}

	c.SetState(sdk.PluginStateReady, "configured")
	return nil
}

func (c *ClamAVPlugin) Start(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Verify clamd is available
	if err := c.connectToClamd(); err != nil {
		c.SetState(sdk.PluginStateError, fmt.Sprintf("clamd not available: %v", err))
		return fmt.Errorf("failed to connect to clamd: %w", err)
	}

	// Get version info
	version, err := c.getVersionLocked()
	if err != nil {
		c.logger("warning: could not get clamd version: %v", err)
	} else {
		c.version = version
	}

	c.SetState(sdk.PluginStateRunning, fmt.Sprintf("connected to clamd (%s)", c.version))
	c.logger("started: connected to clamd at %s", c.socketPath)
	return nil
}

func (c *ClamAVPlugin) Stop(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.conn != nil {
		c.conn.Close()
		c.conn = nil
	}

	c.SetState(sdk.PluginStateStopped, "disconnected")
	c.logger("stopped")
	return nil
}

func (c *ClamAVPlugin) Health() sdk.PluginHealth {
	c.mu.RLock()
	defer c.mu.RUnlock()

	health := c.BaseServicePlugin.Health()

	// Add metrics
	health.Metrics = map[string]interface{}{
		"scans_completed":   c.scansCompleted,
		"threats_detected":  c.threatsDetected,
		"error_count":       c.errorCount,
		"clamd_version":     c.version,
		"socket_path":       c.socketPath,
	}

	if !c.lastScanTime.IsZero() {
		health.Metrics["last_scan_time"] = c.lastScanTime.Format(time.RFC3339)
	}

	return health
}

func (c *ClamAVPlugin) Execute(ctx context.Context, action string, params map[string]interface{}) (map[string]interface{}, error) {
	switch action {
	case "scan_file":
		return c.executeScanFile(ctx, params)
	case "scan_directory":
		return c.executeScanDirectory(ctx, params)
	case "scan_stream":
		return c.executeScanStream(ctx, params)
	case "update_database":
		return c.executeUpdateDatabase(ctx, params)
	case "get_status":
		return c.executeGetStatus(ctx, params)
	case "get_version":
		return c.executeGetVersion(ctx, params)
	case "reload_database":
		return c.executeReloadDatabase(ctx, params)
	case "get_stats":
		return c.executeGetStats(ctx, params)
	default:
		return nil, fmt.Errorf("unknown action: %s", action)
	}
}

// connectToClamd establishes a connection to the clamd socket
func (c *ClamAVPlugin) connectToClamd() error {
	if c.conn != nil {
		c.conn.Close()
	}

	conn, err := net.DialTimeout("unix", c.socketPath, 5*time.Second)
	if err != nil {
		return fmt.Errorf("failed to connect to clamd socket %s: %w", c.socketPath, err)
	}

	c.conn = conn
	return nil
}

// sendCommand sends a command to clamd and returns the response
func (c *ClamAVPlugin) sendCommand(ctx context.Context, command string) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	return c.sendCommandLocked(ctx, command)
}

func (c *ClamAVPlugin) sendCommandLocked(ctx context.Context, command string) (string, error) {
	// Reconnect if needed
	if c.conn == nil {
		if err := c.connectToClamd(); err != nil {
			return "", err
		}
	}

	// Set deadline based on context or default timeout
	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = time.Now().Add(30 * time.Second)
	}
	c.conn.SetDeadline(deadline)

	// Send command using zINSTREAM format for better compatibility
	_, err := fmt.Fprintf(c.conn, "n%s\n", command)
	if err != nil {
		c.conn.Close()
		c.conn = nil
		return "", fmt.Errorf("failed to send command: %w", err)
	}

	// Read response
	reader := bufio.NewReader(c.conn)
	response, err := reader.ReadString('\n')
	if err != nil && err != io.EOF {
		c.conn.Close()
		c.conn = nil
		return "", fmt.Errorf("failed to read response: %w", err)
	}

	// Close and reset connection for next command (clamd closes after each command)
	c.conn.Close()
	c.conn = nil

	return strings.TrimSpace(response), nil
}

func (c *ClamAVPlugin) getVersionLocked() (string, error) {
	conn, err := net.DialTimeout("unix", c.socketPath, 5*time.Second)
	if err != nil {
		return "", err
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(5 * time.Second))
	fmt.Fprintf(conn, "nVERSION\n")

	reader := bufio.NewReader(conn)
	response, err := reader.ReadString('\n')
	if err != nil && err != io.EOF {
		return "", err
	}

	return strings.TrimSpace(response), nil
}

// executeScanFile scans a single file
func (c *ClamAVPlugin) executeScanFile(ctx context.Context, params map[string]interface{}) (map[string]interface{}, error) {
	path, ok := params["path"].(string)
	if !ok || path == "" {
		return nil, fmt.Errorf("path parameter is required")
	}

	// Validate path exists
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("path not accessible: %w", err)
	}

	if info.IsDir() {
		return nil, fmt.Errorf("path is a directory, use scan_directory action")
	}

	result := c.scanFile(ctx, path)

	c.mu.Lock()
	c.scansCompleted++
	c.lastScanTime = time.Now()
	if result.Status == "infected" {
		c.threatsDetected++
	}
	if result.Status == "error" {
		c.errorCount++
	}
	c.mu.Unlock()

	return map[string]interface{}{
		"result": result,
	}, nil
}

// scanFile performs the actual file scan
func (c *ClamAVPlugin) scanFile(ctx context.Context, path string) ScanResult {
	start := time.Now()
	result := ScanResult{
		Path:      path,
		ScannedAt: start,
	}

	// Get file info
	info, err := os.Stat(path)
	if err != nil {
		result.Status = "error"
		result.ErrorMsg = err.Error()
		result.Duration = time.Since(start).String()
		return result
	}
	result.Size = info.Size()
	result.IsDirectory = info.IsDir()

	// Send SCAN command to clamd
	absPath, err := filepath.Abs(path)
	if err != nil {
		result.Status = "error"
		result.ErrorMsg = err.Error()
		result.Duration = time.Since(start).String()
		return result
	}

	response, err := c.sendCommand(ctx, fmt.Sprintf("SCAN %s", absPath))
	if err != nil {
		result.Status = "error"
		result.ErrorMsg = err.Error()
		result.Duration = time.Since(start).String()
		return result
	}

	// Parse response: "/path/to/file: OK" or "/path/to/file: ThreatName FOUND"
	result.Duration = time.Since(start).String()

	if strings.HasSuffix(response, " OK") {
		result.Status = "clean"
	} else if strings.Contains(response, " FOUND") {
		result.Status = "infected"
		// Extract threat name
		parts := strings.SplitN(response, ": ", 2)
		if len(parts) == 2 {
			result.Threat = strings.TrimSuffix(parts[1], " FOUND")
		}
	} else if strings.Contains(response, " ERROR") {
		result.Status = "error"
		parts := strings.SplitN(response, ": ", 2)
		if len(parts) == 2 {
			result.ErrorMsg = parts[1]
		}
	} else {
		result.Status = "error"
		result.ErrorMsg = fmt.Sprintf("unexpected response: %s", response)
	}

	return result
}

// executeScanDirectory scans all files in a directory
func (c *ClamAVPlugin) executeScanDirectory(ctx context.Context, params map[string]interface{}) (map[string]interface{}, error) {
	path, ok := params["path"].(string)
	if !ok || path == "" {
		return nil, fmt.Errorf("path parameter is required")
	}

	recursive := true
	if r, ok := params["recursive"].(bool); ok {
		recursive = r
	}

	// Validate path exists and is a directory
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("path not accessible: %w", err)
	}

	if !info.IsDir() {
		return nil, fmt.Errorf("path is not a directory, use scan_file action")
	}

	start := time.Now()
	summary := ScanSummary{
		Threats: []ScanResult{},
	}

	// Use CONTSCAN for recursive directory scanning (doesn't stop on infected files)
	// or MULTISCAN for multi-threaded scanning
	command := "CONTSCAN"
	if multi, ok := params["multithreaded"].(bool); ok && multi {
		command = "MULTISCAN"
	}

	absPath, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("failed to get absolute path: %w", err)
	}

	// For recursive scan, we use clamd's native recursive scanning
	if !recursive {
		// Non-recursive: scan files directly in directory
		entries, err := os.ReadDir(absPath)
		if err != nil {
			return nil, fmt.Errorf("failed to read directory: %w", err)
		}

		for _, entry := range entries {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			default:
			}

			if entry.IsDir() {
				continue
			}

			filePath := filepath.Join(absPath, entry.Name())
			result := c.scanFile(ctx, filePath)
			summary.TotalFiles++
			summary.ScannedFiles++

			info, _ := entry.Info()
			if info != nil {
				summary.DataScanned += info.Size()
			}

			switch result.Status {
			case "infected":
				summary.InfectedFiles++
				summary.Threats = append(summary.Threats, result)
			case "error":
				summary.Errors++
			}
		}
	} else {
		// Recursive scan using clamd
		response, err := c.sendCommand(ctx, fmt.Sprintf("%s %s", command, absPath))
		if err != nil {
			return nil, fmt.Errorf("scan failed: %w", err)
		}

		// Parse multi-line response
		lines := strings.Split(response, "\n")
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}

			summary.TotalFiles++
			summary.ScannedFiles++

			if strings.HasSuffix(line, " OK") {
				// Clean file
			} else if strings.Contains(line, " FOUND") {
				summary.InfectedFiles++
				parts := strings.SplitN(line, ": ", 2)
				if len(parts) == 2 {
					threat := ScanResult{
						Path:      parts[0],
						Status:    "infected",
						Threat:    strings.TrimSuffix(parts[1], " FOUND"),
						ScannedAt: time.Now(),
					}
					summary.Threats = append(summary.Threats, threat)
				}
			} else if strings.Contains(line, " ERROR") {
				summary.Errors++
			}
		}
	}

	summary.Duration = time.Since(start)

	c.mu.Lock()
	c.scansCompleted++
	c.lastScanTime = time.Now()
	c.threatsDetected += int64(summary.InfectedFiles)
	c.errorCount += int64(summary.Errors)
	c.mu.Unlock()

	return map[string]interface{}{
		"summary": summary,
	}, nil
}

// executeScanStream scans data from a stream (for memory-only scanning)
func (c *ClamAVPlugin) executeScanStream(ctx context.Context, params map[string]interface{}) (map[string]interface{}, error) {
	data, ok := params["data"].([]byte)
	if !ok {
		// Try string
		if str, ok := params["data"].(string); ok {
			data = []byte(str)
		} else {
			return nil, fmt.Errorf("data parameter is required ([]byte or string)")
		}
	}

	start := time.Now()

	// Use INSTREAM command for scanning data
	c.mu.Lock()
	if c.conn != nil {
		c.conn.Close()
		c.conn = nil
	}

	conn, err := net.DialTimeout("unix", c.socketPath, 5*time.Second)
	if err != nil {
		c.mu.Unlock()
		return nil, fmt.Errorf("failed to connect to clamd: %w", err)
	}

	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = time.Now().Add(c.scanTimeout)
	}
	conn.SetDeadline(deadline)

	// Send INSTREAM command
	_, err = fmt.Fprintf(conn, "nINSTREAM\n")
	if err != nil {
		conn.Close()
		c.mu.Unlock()
		return nil, fmt.Errorf("failed to send command: %w", err)
	}

	// Send data in chunks with length prefix
	chunkSize := 2048
	for i := 0; i < len(data); i += chunkSize {
		end := i + chunkSize
		if end > len(data) {
			end = len(data)
		}
		chunk := data[i:end]

		// Write 4-byte big-endian length prefix
		length := uint32(len(chunk))
		lengthBytes := []byte{
			byte(length >> 24),
			byte(length >> 16),
			byte(length >> 8),
			byte(length),
		}
		conn.Write(lengthBytes)
		conn.Write(chunk)
	}

	// Send zero-length chunk to indicate end of stream
	conn.Write([]byte{0, 0, 0, 0})

	// Read response
	reader := bufio.NewReader(conn)
	response, err := reader.ReadString('\n')
	conn.Close()
	c.mu.Unlock()

	if err != nil && err != io.EOF {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	response = strings.TrimSpace(response)
	duration := time.Since(start)

	result := ScanResult{
		Path:      "stream",
		Size:      int64(len(data)),
		ScannedAt: start,
		Duration:  duration.String(),
	}

	// Parse response: "stream: OK" or "stream: ThreatName FOUND"
	if strings.HasSuffix(response, " OK") {
		result.Status = "clean"
	} else if strings.Contains(response, " FOUND") {
		result.Status = "infected"
		parts := strings.SplitN(response, ": ", 2)
		if len(parts) == 2 {
			result.Threat = strings.TrimSuffix(parts[1], " FOUND")
		}
	} else {
		result.Status = "error"
		result.ErrorMsg = fmt.Sprintf("unexpected response: %s", response)
	}

	c.mu.Lock()
	c.scansCompleted++
	c.lastScanTime = time.Now()
	if result.Status == "infected" {
		c.threatsDetected++
	}
	if result.Status == "error" {
		c.errorCount++
	}
	c.mu.Unlock()

	return map[string]interface{}{
		"result": result,
	}, nil
}

// executeUpdateDatabase runs freshclam to update virus definitions
func (c *ClamAVPlugin) executeUpdateDatabase(ctx context.Context, params map[string]interface{}) (map[string]interface{}, error) {
	// Find freshclam
	freshclam, err := exec.LookPath("freshclam")
	if err != nil {
		return nil, fmt.Errorf("freshclam not found in PATH: %w", err)
	}

	// Run freshclam
	cmd := exec.CommandContext(ctx, freshclam, "--stdout")

	output, err := cmd.CombinedOutput()
	if err != nil {
		return map[string]interface{}{
			"success": false,
			"output":  string(output),
			"error":   err.Error(),
		}, nil
	}

	// Parse output for update information
	result := map[string]interface{}{
		"success": true,
		"output":  string(output),
	}

	// Extract database versions from output
	versionRegex := regexp.MustCompile(`(\w+)\.cvd/cld version:?\s*(\d+)`)
	matches := versionRegex.FindAllStringSubmatch(string(output), -1)
	databases := []map[string]string{}
	for _, match := range matches {
		if len(match) >= 3 {
			databases = append(databases, map[string]string{
				"name":    match[1],
				"version": match[2],
			})
		}
	}
	result["databases"] = databases

	return result, nil
}

// executeGetStatus returns the current clamd status
func (c *ClamAVPlugin) executeGetStatus(ctx context.Context, params map[string]interface{}) (map[string]interface{}, error) {
	status := ClamdStatus{
		SocketPath: c.socketPath,
	}

	// Get version
	version, err := c.sendCommand(ctx, "VERSION")
	if err != nil {
		status.Running = false
		return map[string]interface{}{
			"status": status,
			"error":  err.Error(),
		}, nil
	}

	status.Running = true
	status.Version = version

	// Get stats
	stats, err := c.sendCommand(ctx, "STATS")
	if err == nil {
		// Parse stats output
		lines := strings.Split(stats, "\n")
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "POOLS:") {
				// Parse thread info
			} else if strings.HasPrefix(line, "QUEUE:") {
				if parts := strings.Fields(line); len(parts) >= 2 {
					if q, err := strconv.Atoi(parts[1]); err == nil {
						status.Queue = q
					}
				}
			} else if strings.HasPrefix(line, "THREADS:") {
				if parts := strings.Fields(line); len(parts) >= 4 {
					// Format: "THREADS: live X idle Y max Z"
					for i, p := range parts {
						if p == "live" && i+1 < len(parts) {
							if t, err := strconv.Atoi(parts[i+1]); err == nil {
								status.Threads = t
							}
						}
					}
				}
			}
		}
	}

	// Get database info
	dbInfos, totalSigs := c.getDatabaseInfo()
	status.DatabaseInfo = dbInfos
	status.TotalSignatures = totalSigs

	return map[string]interface{}{
		"status": status,
	}, nil
}

// getDatabaseInfo reads ClamAV database information
func (c *ClamAVPlugin) getDatabaseInfo() ([]DatabaseInfo, int64) {
	var infos []DatabaseInfo
	var totalSigs int64

	// Check common database files
	dbFiles := []string{"main.cvd", "main.cld", "daily.cvd", "daily.cld", "bytecode.cvd", "bytecode.cld"}

	c.mu.RLock()
	dbDir := c.dbDir
	c.mu.RUnlock()

	for _, dbFile := range dbFiles {
		path := filepath.Join(dbDir, dbFile)
		info, err := os.Stat(path)
		if err != nil {
			continue
		}

		dbInfo := DatabaseInfo{
			Name:        strings.TrimSuffix(dbFile, filepath.Ext(dbFile)),
			LastUpdated: info.ModTime(),
		}

		// Try to read CVD/CLD header for more info
		f, err := os.Open(path)
		if err == nil {
			header := make([]byte, 512)
			if n, err := f.Read(header); err == nil && n >= 512 {
				// CVD header format: ClamAV-VDB:buildtime:version:sigs:...
				headerStr := string(header)
				if strings.HasPrefix(headerStr, "ClamAV-VDB:") {
					parts := strings.Split(headerStr, ":")
					if len(parts) >= 4 {
						dbInfo.Version = parts[2]
						if sigs, err := strconv.ParseInt(parts[3], 10, 64); err == nil {
							dbInfo.Signatures = sigs
							totalSigs += sigs
						}
						if bt, err := time.Parse("02 Jan 2006 15-04 -0700", parts[1]); err == nil {
							dbInfo.BuildTime = bt
						}
					}
				}
			}
			f.Close()
		}

		infos = append(infos, dbInfo)
	}

	return infos, totalSigs
}

// executeGetVersion returns the clamd version
func (c *ClamAVPlugin) executeGetVersion(ctx context.Context, params map[string]interface{}) (map[string]interface{}, error) {
	version, err := c.sendCommand(ctx, "VERSION")
	if err != nil {
		return nil, fmt.Errorf("failed to get version: %w", err)
	}

	return map[string]interface{}{
		"version": version,
	}, nil
}

// executeReloadDatabase tells clamd to reload its databases
func (c *ClamAVPlugin) executeReloadDatabase(ctx context.Context, params map[string]interface{}) (map[string]interface{}, error) {
	response, err := c.sendCommand(ctx, "RELOAD")
	if err != nil {
		return nil, fmt.Errorf("failed to reload database: %w", err)
	}

	success := strings.Contains(response, "RELOADING")

	return map[string]interface{}{
		"success":  success,
		"response": response,
	}, nil
}

// executeGetStats returns plugin statistics
func (c *ClamAVPlugin) executeGetStats(ctx context.Context, params map[string]interface{}) (map[string]interface{}, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	return map[string]interface{}{
		"scans_completed":   c.scansCompleted,
		"threats_detected":  c.threatsDetected,
		"error_count":       c.errorCount,
		"last_scan_time":    c.lastScanTime.Format(time.RFC3339),
		"clamd_version":     c.version,
	}, nil
}

func main() {
	sdk.ServeServicePlugin(&ClamAVPlugin{})
}
