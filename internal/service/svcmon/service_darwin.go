//go:build darwin

package svcmon

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/afterdarksys/afterdark-darkd/internal/models"
	"howett.net/plist"
)

// LaunchDaemon represents a macOS launch daemon/agent plist
type LaunchDaemon struct {
	Label            string      `plist:"Label"`
	ProgramArguments []string    `plist:"ProgramArguments,omitempty"`
	Program          string      `plist:"Program,omitempty"`
	RunAtLoad        bool        `plist:"RunAtLoad,omitempty"`
	KeepAlive        interface{} `plist:"KeepAlive,omitempty"`
	Disabled         bool        `plist:"Disabled,omitempty"`
	OnDemand         bool        `plist:"OnDemand,omitempty"`
}

// launchDaemonPaths are directories containing launch plists
var launchDaemonPaths = []string{
	"/System/Library/LaunchDaemons",
	"/Library/LaunchDaemons",
	"/System/Library/LaunchAgents",
	"/Library/LaunchAgents",
}

// scanDarwinNative scans services on macOS using native plist parsing
// instead of exec.Command("launchctl", "list")
func (s *Service) scanDarwinNative() ([]models.SystemService, error) {
	services := make([]models.SystemService, 0)
	seen := make(map[string]bool)

	// Also scan user launch agents if we have access
	home := os.Getenv("HOME")
	if home != "" {
		userAgentPath := filepath.Join(home, "Library/LaunchAgents")
		launchDaemonPaths = append(launchDaemonPaths, userAgentPath)
	}

	for _, dir := range launchDaemonPaths {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue // Skip inaccessible directories
		}

		for _, entry := range entries {
			if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".plist") {
				continue
			}

			plistPath := filepath.Join(dir, entry.Name())
			svc, err := s.parseLaunchPlist(plistPath)
			if err != nil {
				continue
			}

			// Avoid duplicates
			if seen[svc.Name] {
				continue
			}
			seen[svc.Name] = true

			services = append(services, svc)
		}
	}

	// Determine running status by checking for running processes
	s.updateDarwinRunningStatus(services)

	return services, nil
}

// parseLaunchPlist parses a single launchd plist file
func (s *Service) parseLaunchPlist(path string) (models.SystemService, error) {
	svc := models.SystemService{
		Status: "unknown",
	}

	file, err := os.Open(path)
	if err != nil {
		return svc, err
	}
	defer file.Close()

	var daemon LaunchDaemon
	decoder := plist.NewDecoder(file)
	if err := decoder.Decode(&daemon); err != nil {
		return svc, err
	}

	svc.Name = daemon.Label
	if svc.Name == "" {
		svc.Name = strings.TrimSuffix(filepath.Base(path), ".plist")
	}

	// Determine executable path
	if daemon.Program != "" {
		svc.Executable = daemon.Program
	} else if len(daemon.ProgramArguments) > 0 {
		svc.Executable = daemon.ProgramArguments[0]
	}

	// Determine enabled status
	svc.Enabled = !daemon.Disabled

	// Initial status based on configuration
	if daemon.RunAtLoad || daemon.KeepAlive != nil {
		svc.Status = "enabled"
	} else {
		svc.Status = "disabled"
	}

	return svc, nil
}

// updateDarwinRunningStatus checks /var/run/launchd-*.pid and /var/run/*.pid
// to determine which services are actually running
func (s *Service) updateDarwinRunningStatus(services []models.SystemService) {
	// Read from /var/run to find running daemons
	runDir := "/var/run"
	entries, err := os.ReadDir(runDir)
	if err != nil {
		return
	}

	runningPids := make(map[string]bool)
	for _, entry := range entries {
		if strings.HasSuffix(entry.Name(), ".pid") {
			name := strings.TrimSuffix(entry.Name(), ".pid")
			runningPids[name] = true
		}
	}

	// Also check /Library/LaunchDaemons/.running or similar markers
	// For a more accurate check, we'd need to use the private launchd APIs
	// or parse the launchctl output (fallback)

	for i := range services {
		// Simple heuristic: check if a PID file exists
		baseName := filepath.Base(services[i].Name)
		if runningPids[baseName] {
			services[i].Status = "running"
		}
	}
}

// getDarwinServiceInfo gets detailed info about a specific service
func (s *Service) getDarwinServiceInfo(label string) (*models.SystemService, error) {
	for _, dir := range launchDaemonPaths {
		err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() || !strings.HasSuffix(d.Name(), ".plist") {
				return nil
			}

			svc, parseErr := s.parseLaunchPlist(path)
			if parseErr == nil && svc.Name == label {
				return fs.SkipAll // Found it, stop walking
			}
			return nil
		})
		if err == fs.SkipAll {
			// Found the service
			// Re-parse and return
			for _, subDir := range launchDaemonPaths {
				plistPath := filepath.Join(subDir, label+".plist")
				if svc, err := s.parseLaunchPlist(plistPath); err == nil {
					return &svc, nil
				}
			}
		}
	}
	return nil, os.ErrNotExist
}
