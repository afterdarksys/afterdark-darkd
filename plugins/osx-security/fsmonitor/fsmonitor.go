// Package fsmonitor provides file system monitoring for macOS security-sensitive paths
//
// This module monitors:
// - Directory Services database changes (/var/db/dslocal/)
// - Keychain file changes
// - User account modifications
// - Launch daemons and agents
// - System extensions
// - Privacy/TCC database changes
//
// Uses fsnotify for cross-platform compatibility, with macOS-specific enhancements
//
// Build: Part of osx-security plugin for afterdark-darkd
package fsmonitor

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
)

// EventType represents the type of filesystem event
type EventType string

const (
	EventCreate EventType = "create"
	EventWrite  EventType = "write"
	EventRemove EventType = "remove"
	EventRename EventType = "rename"
	EventChmod  EventType = "chmod"
)

// SecurityCategory represents the category of monitored path
type SecurityCategory string

const (
	CategoryDirectoryServices SecurityCategory = "directory_services"
	CategoryKeychain          SecurityCategory = "keychain"
	CategoryLaunchDaemon      SecurityCategory = "launch_daemon"
	CategoryLaunchAgent       SecurityCategory = "launch_agent"
	CategorySystemExtension   SecurityCategory = "system_extension"
	CategoryPrivacyTCC        SecurityCategory = "privacy_tcc"
	CategorySudoers           SecurityCategory = "sudoers"
	CategoryPAM               SecurityCategory = "pam"
	CategorySSH               SecurityCategory = "ssh"
	CategoryCron              SecurityCategory = "cron"
	CategoryUserConfig        SecurityCategory = "user_config"
	CategoryUnknown           SecurityCategory = "unknown"
)

// Event represents a monitored filesystem event
type Event struct {
	Path       string           `json:"path"`
	Type       EventType        `json:"type"`
	Category   SecurityCategory `json:"category"`
	Severity   string           `json:"severity"` // critical, high, medium, low
	Timestamp  time.Time        `json:"timestamp"`
	User       string           `json:"user,omitempty"`
	Process    string           `json:"process,omitempty"`
	Details    map[string]interface{} `json:"details,omitempty"`
}

// MonitorConfig specifies which paths to monitor
type MonitorConfig struct {
	// System paths (require root)
	MonitorDirectoryServices bool `json:"monitor_directory_services"`
	MonitorLaunchDaemons     bool `json:"monitor_launch_daemons"`
	MonitorSystemExtensions  bool `json:"monitor_system_extensions"`
	MonitorPrivacyTCC        bool `json:"monitor_privacy_tcc"`
	MonitorSudoers           bool `json:"monitor_sudoers"`
	MonitorPAM               bool `json:"monitor_pam"`
	MonitorSSH               bool `json:"monitor_ssh"`
	MonitorCron              bool `json:"monitor_cron"`

	// User paths (current user)
	MonitorUserKeychain      bool `json:"monitor_user_keychain"`
	MonitorUserLaunchAgents  bool `json:"monitor_user_launch_agents"`
	MonitorUserSSH           bool `json:"monitor_user_ssh"`

	// Custom paths
	CustomPaths []string `json:"custom_paths,omitempty"`
}

// DefaultConfig returns a sensible default monitoring configuration
func DefaultConfig() MonitorConfig {
	return MonitorConfig{
		MonitorDirectoryServices: true,
		MonitorLaunchDaemons:     true,
		MonitorSystemExtensions:  true,
		MonitorPrivacyTCC:        true,
		MonitorSudoers:           true,
		MonitorPAM:               true,
		MonitorSSH:               true,
		MonitorCron:              true,
		MonitorUserKeychain:      true,
		MonitorUserLaunchAgents:  true,
		MonitorUserSSH:           true,
	}
}

// EventHandler is called when a filesystem event occurs
type EventHandler func(Event)

// Monitor monitors security-sensitive filesystem paths
type Monitor struct {
	config   MonitorConfig
	watcher  *fsnotify.Watcher
	handler  EventHandler
	running  bool
	mu       sync.RWMutex
	stopCh   chan struct{}
	paths    map[string]SecurityCategory
	homeDir  string
}

// NewMonitor creates a new filesystem monitor
func NewMonitor(config MonitorConfig, handler EventHandler) (*Monitor, error) {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, fmt.Errorf("failed to create watcher: %w", err)
	}

	homeDir, _ := os.UserHomeDir()

	m := &Monitor{
		config:  config,
		watcher: watcher,
		handler: handler,
		stopCh:  make(chan struct{}),
		paths:   make(map[string]SecurityCategory),
		homeDir: homeDir,
	}

	return m, nil
}

// Start begins monitoring
func (m *Monitor) Start() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.running {
		return fmt.Errorf("monitor already running")
	}

	// Add paths based on config
	if err := m.setupPaths(); err != nil {
		return err
	}

	m.running = true
	go m.eventLoop()

	return nil
}

// Stop stops monitoring
func (m *Monitor) Stop() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if !m.running {
		return nil
	}

	close(m.stopCh)
	m.running = false

	return m.watcher.Close()
}

// setupPaths adds paths to watch based on configuration
func (m *Monitor) setupPaths() error {
	// Directory Services
	if m.config.MonitorDirectoryServices {
		m.addPath("/var/db/dslocal/nodes/Default/users", CategoryDirectoryServices)
		m.addPath("/var/db/dslocal/nodes/Default/groups", CategoryDirectoryServices)
	}

	// Launch Daemons (system-wide)
	if m.config.MonitorLaunchDaemons {
		m.addPath("/Library/LaunchDaemons", CategoryLaunchDaemon)
		m.addPath("/System/Library/LaunchDaemons", CategoryLaunchDaemon)
	}

	// System Extensions
	if m.config.MonitorSystemExtensions {
		m.addPath("/Library/SystemExtensions", CategorySystemExtension)
		m.addPath("/Library/Extensions", CategorySystemExtension)
	}

	// Privacy TCC database
	if m.config.MonitorPrivacyTCC {
		m.addPath("/Library/Application Support/com.apple.TCC", CategoryPrivacyTCC)
		if m.homeDir != "" {
			m.addPath(filepath.Join(m.homeDir, "Library/Application Support/com.apple.TCC"), CategoryPrivacyTCC)
		}
	}

	// Sudoers
	if m.config.MonitorSudoers {
		m.addPath("/etc/sudoers", CategorySudoers)
		m.addPath("/etc/sudoers.d", CategorySudoers)
		m.addPath("/private/etc/sudoers", CategorySudoers)
		m.addPath("/private/etc/sudoers.d", CategorySudoers)
	}

	// PAM configuration
	if m.config.MonitorPAM {
		m.addPath("/etc/pam.d", CategoryPAM)
		m.addPath("/private/etc/pam.d", CategoryPAM)
	}

	// SSH system configuration
	if m.config.MonitorSSH {
		m.addPath("/etc/ssh", CategorySSH)
		m.addPath("/private/etc/ssh", CategorySSH)
	}

	// Cron
	if m.config.MonitorCron {
		m.addPath("/etc/crontab", CategoryCron)
		m.addPath("/var/at/tabs", CategoryCron)
		m.addPath("/usr/lib/cron/tabs", CategoryCron)
	}

	// User keychain
	if m.config.MonitorUserKeychain && m.homeDir != "" {
		m.addPath(filepath.Join(m.homeDir, "Library/Keychains"), CategoryKeychain)
	}

	// User launch agents
	if m.config.MonitorUserLaunchAgents && m.homeDir != "" {
		m.addPath(filepath.Join(m.homeDir, "Library/LaunchAgents"), CategoryLaunchAgent)
		m.addPath("/Library/LaunchAgents", CategoryLaunchAgent)
	}

	// User SSH
	if m.config.MonitorUserSSH && m.homeDir != "" {
		m.addPath(filepath.Join(m.homeDir, ".ssh"), CategorySSH)
	}

	// Custom paths
	for _, path := range m.config.CustomPaths {
		m.addPath(path, CategoryUnknown)
	}

	return nil
}

// addPath adds a path to the watch list if it exists
func (m *Monitor) addPath(path string, category SecurityCategory) {
	// Check if path exists
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return
	}

	if err := m.watcher.Add(path); err != nil {
		// Silently skip paths we can't watch (permissions)
		return
	}

	m.paths[path] = category

	// Also watch subdirectories for directories
	if info, err := os.Stat(path); err == nil && info.IsDir() {
		filepath.Walk(path, func(subpath string, info os.FileInfo, err error) error {
			if err != nil {
				return nil
			}
			if info.IsDir() && subpath != path {
				m.watcher.Add(subpath)
				m.paths[subpath] = category
			}
			return nil
		})
	}
}

// eventLoop processes filesystem events
func (m *Monitor) eventLoop() {
	for {
		select {
		case <-m.stopCh:
			return
		case event, ok := <-m.watcher.Events:
			if !ok {
				return
			}
			m.processEvent(event)
		case err, ok := <-m.watcher.Errors:
			if !ok {
				return
			}
			// Log error but continue
			_ = err
		}
	}
}

// processEvent converts fsnotify event to our Event type and calls handler
func (m *Monitor) processEvent(fsEvent fsnotify.Event) {
	event := Event{
		Path:      fsEvent.Name,
		Timestamp: time.Now(),
		Category:  m.categorize(fsEvent.Name),
		Details:   make(map[string]interface{}),
	}

	// Determine event type
	switch {
	case fsEvent.Op&fsnotify.Create == fsnotify.Create:
		event.Type = EventCreate
	case fsEvent.Op&fsnotify.Write == fsnotify.Write:
		event.Type = EventWrite
	case fsEvent.Op&fsnotify.Remove == fsnotify.Remove:
		event.Type = EventRemove
	case fsEvent.Op&fsnotify.Rename == fsnotify.Rename:
		event.Type = EventRename
	case fsEvent.Op&fsnotify.Chmod == fsnotify.Chmod:
		event.Type = EventChmod
	}

	// Determine severity based on category and event type
	event.Severity = m.determineSeverity(event)

	// Add file details if available
	if info, err := os.Stat(fsEvent.Name); err == nil {
		event.Details["size"] = info.Size()
		event.Details["mode"] = info.Mode().String()
		event.Details["mod_time"] = info.ModTime()
	}

	// Call handler
	if m.handler != nil {
		m.handler(event)
	}
}

// categorize determines the security category of a path
func (m *Monitor) categorize(path string) SecurityCategory {
	// Check exact matches first
	for watchPath, category := range m.paths {
		if strings.HasPrefix(path, watchPath) {
			return category
		}
	}

	// Pattern matching for paths
	switch {
	case strings.Contains(path, "dslocal"):
		return CategoryDirectoryServices
	case strings.Contains(path, "Keychain"):
		return CategoryKeychain
	case strings.Contains(path, "LaunchDaemon"):
		return CategoryLaunchDaemon
	case strings.Contains(path, "LaunchAgent"):
		return CategoryLaunchAgent
	case strings.Contains(path, "SystemExtension") || strings.Contains(path, "Extensions"):
		return CategorySystemExtension
	case strings.Contains(path, "TCC"):
		return CategoryPrivacyTCC
	case strings.Contains(path, "sudoers"):
		return CategorySudoers
	case strings.Contains(path, "pam.d"):
		return CategoryPAM
	case strings.Contains(path, ".ssh") || strings.Contains(path, "/ssh/"):
		return CategorySSH
	case strings.Contains(path, "cron"):
		return CategoryCron
	}

	return CategoryUnknown
}

// determineSeverity determines the severity of an event
func (m *Monitor) determineSeverity(event Event) string {
	// Critical events
	criticalCategories := map[SecurityCategory]bool{
		CategoryDirectoryServices: true,
		CategorySudoers:           true,
		CategoryPAM:               true,
	}

	highCategories := map[SecurityCategory]bool{
		CategoryLaunchDaemon:     true,
		CategorySystemExtension:  true,
		CategoryPrivacyTCC:       true,
	}

	mediumCategories := map[SecurityCategory]bool{
		CategoryLaunchAgent: true,
		CategorySSH:         true,
		CategoryCron:        true,
	}

	// Create and Write events are higher severity
	if event.Type == EventCreate || event.Type == EventWrite {
		if criticalCategories[event.Category] {
			return "critical"
		}
		if highCategories[event.Category] {
			return "high"
		}
		if mediumCategories[event.Category] {
			return "medium"
		}
	}

	// Remove events
	if event.Type == EventRemove {
		if criticalCategories[event.Category] {
			return "high"
		}
		return "medium"
	}

	// Chmod events
	if event.Type == EventChmod {
		if criticalCategories[event.Category] {
			return "high"
		}
		return "low"
	}

	return "low"
}

// GetMonitoredPaths returns all currently monitored paths
func (m *Monitor) GetMonitoredPaths() map[string]SecurityCategory {
	m.mu.RLock()
	defer m.mu.RUnlock()

	paths := make(map[string]SecurityCategory)
	for k, v := range m.paths {
		paths[k] = v
	}
	return paths
}

// AddCustomPath adds a custom path to monitor at runtime
func (m *Monitor) AddCustomPath(path string, category SecurityCategory) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, err := os.Stat(path); os.IsNotExist(err) {
		return fmt.Errorf("path does not exist: %s", path)
	}

	if err := m.watcher.Add(path); err != nil {
		return fmt.Errorf("failed to watch path: %w", err)
	}

	m.paths[path] = category
	return nil
}

// RemoveCustomPath stops monitoring a custom path
func (m *Monitor) RemoveCustomPath(path string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if err := m.watcher.Remove(path); err != nil {
		return err
	}

	delete(m.paths, path)
	return nil
}

// IsRunning returns whether the monitor is currently running
func (m *Monitor) IsRunning() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.running
}

// Stats returns monitoring statistics
func (m *Monitor) Stats() map[string]interface{} {
	m.mu.RLock()
	defer m.mu.RUnlock()

	categoryCounts := make(map[string]int)
	for _, cat := range m.paths {
		categoryCounts[string(cat)]++
	}

	return map[string]interface{}{
		"running":         m.running,
		"total_paths":     len(m.paths),
		"by_category":     categoryCounts,
	}
}
