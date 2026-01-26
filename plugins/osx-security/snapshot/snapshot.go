// Package snapshot provides state snapshotting and diff comparison for macOS security state
//
// This module:
// - Takes point-in-time snapshots of user accounts, groups, keychains, and system config
// - Compares snapshots to detect changes
// - Persists snapshots for historical analysis
// - Generates detailed diff reports
//
// Build: Part of osx-security plugin for afterdark-darkd
package snapshot

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/afterdarksys/afterdark-darkd/plugins/osx-security/dsaudit"
	"github.com/afterdarksys/afterdark-darkd/plugins/osx-security/keywatch"
)

// Snapshot represents a point-in-time security state
type Snapshot struct {
	ID           string                 `json:"id"`
	Timestamp    time.Time              `json:"timestamp"`
	MacOSVersion string                 `json:"macos_version"`
	Hostname     string                 `json:"hostname"`
	Users        []dsaudit.User         `json:"users"`
	Groups       []dsaudit.Group        `json:"groups"`
	KeychainMeta *keywatch.AnalysisResult `json:"keychain_meta,omitempty"`
	LaunchItems  []LaunchItem           `json:"launch_items"`
	SystemConfig SystemConfig           `json:"system_config"`
	Hash         string                 `json:"hash"`
	Metadata     map[string]interface{} `json:"metadata,omitempty"`
}

// LaunchItem represents a launch daemon or agent
type LaunchItem struct {
	Path        string            `json:"path"`
	Label       string            `json:"label"`
	Program     string            `json:"program,omitempty"`
	ProgramArgs []string          `json:"program_args,omitempty"`
	RunAtLoad   bool              `json:"run_at_load"`
	KeepAlive   bool              `json:"keep_alive"`
	Disabled    bool              `json:"disabled"`
	Type        string            `json:"type"` // daemon, agent
	Hash        string            `json:"hash"`
}

// SystemConfig represents security-relevant system configuration
type SystemConfig struct {
	SIPEnabled       bool              `json:"sip_enabled"`
	GatekeeperStatus string            `json:"gatekeeper_status"`
	FirewallEnabled  bool              `json:"firewall_enabled"`
	FileVaultEnabled bool              `json:"filevault_enabled"`
	RemoteLogin      bool              `json:"remote_login"`
	RemoteDesktop    bool              `json:"remote_desktop"`
	SSHConfig        map[string]string `json:"ssh_config,omitempty"`
}

// DiffResult contains the differences between two snapshots
type DiffResult struct {
	OlderSnapshot   string          `json:"older_snapshot"`
	NewerSnapshot   string          `json:"newer_snapshot"`
	TimeDelta       time.Duration   `json:"time_delta"`
	Changes         []Change        `json:"changes"`
	TotalChanges    int             `json:"total_changes"`
	CriticalChanges int             `json:"critical_changes"`
	HighChanges     int             `json:"high_changes"`
	Summary         string          `json:"summary"`
}

// Change represents a single change between snapshots
type Change struct {
	Type        string                 `json:"type"`     // user, group, keychain, launch_item, system_config
	Action      string                 `json:"action"`   // added, removed, modified
	Severity    string                 `json:"severity"` // critical, high, medium, low, info
	Path        string                 `json:"path,omitempty"`
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	OldValue    interface{}            `json:"old_value,omitempty"`
	NewValue    interface{}            `json:"new_value,omitempty"`
	Details     map[string]interface{} `json:"details,omitempty"`
}

// Manager handles snapshot creation, storage, and comparison
type Manager struct {
	snapshotDir   string
	dsAuditor     *dsaudit.Auditor
	keyAnalyzer   *keywatch.Analyzer
	mu            sync.RWMutex
	latestSnapshot *Snapshot
}

// NewManager creates a new snapshot manager
func NewManager(snapshotDir string) (*Manager, error) {
	if err := os.MkdirAll(snapshotDir, 0700); err != nil {
		return nil, fmt.Errorf("failed to create snapshot directory: %w", err)
	}

	return &Manager{
		snapshotDir: snapshotDir,
		dsAuditor:   dsaudit.NewAuditor(),
		keyAnalyzer: keywatch.NewAnalyzer(),
	}, nil
}

// TakeSnapshot creates a new snapshot of the current security state
func (m *Manager) TakeSnapshot() (*Snapshot, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	snapshot := &Snapshot{
		ID:        generateID(),
		Timestamp: time.Now(),
		Metadata:  make(map[string]interface{}),
	}

	// Get hostname
	if hostname, err := os.Hostname(); err == nil {
		snapshot.Hostname = hostname
	}

	// Audit Directory Services
	dsResult, err := m.dsAuditor.Audit()
	if err == nil {
		snapshot.Users = dsResult.Users
		snapshot.Groups = dsResult.Groups
		snapshot.MacOSVersion = dsResult.MacOSVersion
	}

	// Analyze keychain (metadata only for security)
	keyResult, err := m.keyAnalyzer.Analyze()
	if err == nil {
		snapshot.KeychainMeta = keyResult
	}

	// Enumerate launch items
	snapshot.LaunchItems = m.enumerateLaunchItems()

	// Get system configuration
	snapshot.SystemConfig = m.getSystemConfig()

	// Compute hash
	snapshot.Hash = m.computeSnapshotHash(snapshot)

	// Store latest
	m.latestSnapshot = snapshot

	return snapshot, nil
}

// SaveSnapshot persists a snapshot to disk
func (m *Manager) SaveSnapshot(snapshot *Snapshot) error {
	filename := fmt.Sprintf("snapshot_%s_%s.json",
		snapshot.Timestamp.Format("20060102_150405"),
		snapshot.ID)
	filepath := filepath.Join(m.snapshotDir, filename)

	data, err := json.MarshalIndent(snapshot, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal snapshot: %w", err)
	}

	if err := os.WriteFile(filepath, data, 0600); err != nil {
		return fmt.Errorf("failed to write snapshot: %w", err)
	}

	return nil
}

// LoadSnapshot loads a snapshot from disk by ID
func (m *Manager) LoadSnapshot(id string) (*Snapshot, error) {
	files, err := os.ReadDir(m.snapshotDir)
	if err != nil {
		return nil, err
	}

	for _, file := range files {
		if strings.Contains(file.Name(), id) {
			filepath := filepath.Join(m.snapshotDir, file.Name())
			data, err := os.ReadFile(filepath)
			if err != nil {
				return nil, err
			}

			var snapshot Snapshot
			if err := json.Unmarshal(data, &snapshot); err != nil {
				return nil, err
			}

			return &snapshot, nil
		}
	}

	return nil, fmt.Errorf("snapshot not found: %s", id)
}

// ListSnapshots returns all available snapshots
func (m *Manager) ListSnapshots() ([]SnapshotInfo, error) {
	files, err := os.ReadDir(m.snapshotDir)
	if err != nil {
		return nil, err
	}

	var snapshots []SnapshotInfo
	for _, file := range files {
		if !strings.HasPrefix(file.Name(), "snapshot_") || !strings.HasSuffix(file.Name(), ".json") {
			continue
		}

		filepath := filepath.Join(m.snapshotDir, file.Name())
		data, err := os.ReadFile(filepath)
		if err != nil {
			continue
		}

		var snapshot Snapshot
		if err := json.Unmarshal(data, &snapshot); err != nil {
			continue
		}

		snapshots = append(snapshots, SnapshotInfo{
			ID:        snapshot.ID,
			Timestamp: snapshot.Timestamp,
			Hostname:  snapshot.Hostname,
			Hash:      snapshot.Hash,
			FilePath:  filepath,
		})
	}

	// Sort by timestamp descending
	sort.Slice(snapshots, func(i, j int) bool {
		return snapshots[i].Timestamp.After(snapshots[j].Timestamp)
	})

	return snapshots, nil
}

// SnapshotInfo contains basic info about a snapshot
type SnapshotInfo struct {
	ID        string    `json:"id"`
	Timestamp time.Time `json:"timestamp"`
	Hostname  string    `json:"hostname"`
	Hash      string    `json:"hash"`
	FilePath  string    `json:"file_path"`
}

// Compare compares two snapshots and returns the differences
func (m *Manager) Compare(older, newer *Snapshot) (*DiffResult, error) {
	result := &DiffResult{
		OlderSnapshot: older.ID,
		NewerSnapshot: newer.ID,
		TimeDelta:     newer.Timestamp.Sub(older.Timestamp),
		Changes:       make([]Change, 0),
	}

	// Compare users
	userChanges := m.compareUsers(older.Users, newer.Users)
	result.Changes = append(result.Changes, userChanges...)

	// Compare groups
	groupChanges := m.compareGroups(older.Groups, newer.Groups)
	result.Changes = append(result.Changes, groupChanges...)

	// Compare launch items
	launchChanges := m.compareLaunchItems(older.LaunchItems, newer.LaunchItems)
	result.Changes = append(result.Changes, launchChanges...)

	// Compare system config
	configChanges := m.compareSystemConfig(older.SystemConfig, newer.SystemConfig)
	result.Changes = append(result.Changes, configChanges...)

	// Count by severity
	for _, change := range result.Changes {
		result.TotalChanges++
		switch change.Severity {
		case "critical":
			result.CriticalChanges++
		case "high":
			result.HighChanges++
		}
	}

	// Generate summary
	result.Summary = m.generateSummary(result)

	return result, nil
}

// compareUsers compares user lists between snapshots
func (m *Manager) compareUsers(older, newer []dsaudit.User) []Change {
	var changes []Change

	olderMap := make(map[string]dsaudit.User)
	for _, u := range older {
		olderMap[u.Name] = u
	}

	newerMap := make(map[string]dsaudit.User)
	for _, u := range newer {
		newerMap[u.Name] = u
	}

	// Find added users
	for name, newUser := range newerMap {
		if _, exists := olderMap[name]; !exists {
			severity := "medium"
			if newUser.IsAdmin {
				severity = "critical"
			}
			changes = append(changes, Change{
				Type:        "user",
				Action:      "added",
				Severity:    severity,
				Name:        name,
				Description: fmt.Sprintf("New user '%s' created (UID: %d, Admin: %v)", name, newUser.UID, newUser.IsAdmin),
				NewValue:    newUser,
				Details: map[string]interface{}{
					"uid":      newUser.UID,
					"admin":    newUser.IsAdmin,
					"home_dir": newUser.HomeDir,
				},
			})
		}
	}

	// Find removed users
	for name, oldUser := range olderMap {
		if _, exists := newerMap[name]; !exists {
			changes = append(changes, Change{
				Type:        "user",
				Action:      "removed",
				Severity:    "medium",
				Name:        name,
				Description: fmt.Sprintf("User '%s' deleted", name),
				OldValue:    oldUser,
			})
		}
	}

	// Find modified users
	for name, newUser := range newerMap {
		if oldUser, exists := olderMap[name]; exists {
			userChanges := m.compareUserDetails(oldUser, newUser)
			changes = append(changes, userChanges...)
		}
	}

	return changes
}

// compareUserDetails compares details of a specific user
func (m *Manager) compareUserDetails(older, newer dsaudit.User) []Change {
	var changes []Change

	// Check privilege escalation
	if newer.IsAdmin && !older.IsAdmin {
		changes = append(changes, Change{
			Type:        "user",
			Action:      "modified",
			Severity:    "critical",
			Name:        newer.Name,
			Description: fmt.Sprintf("User '%s' granted admin privileges", newer.Name),
			OldValue:    older.IsAdmin,
			NewValue:    newer.IsAdmin,
			Details: map[string]interface{}{
				"field":      "admin",
				"old_groups": older.Groups,
				"new_groups": newer.Groups,
			},
		})
	}

	// Check UID changes (suspicious)
	if newer.UID != older.UID {
		changes = append(changes, Change{
			Type:        "user",
			Action:      "modified",
			Severity:    "high",
			Name:        newer.Name,
			Description: fmt.Sprintf("User '%s' UID changed from %d to %d", newer.Name, older.UID, newer.UID),
			OldValue:    older.UID,
			NewValue:    newer.UID,
		})
	}

	// Check shell changes
	if newer.Shell != older.Shell {
		severity := "low"
		if newer.Shell == "/bin/bash" || newer.Shell == "/bin/zsh" {
			severity = "medium"
		}
		changes = append(changes, Change{
			Type:        "user",
			Action:      "modified",
			Severity:    severity,
			Name:        newer.Name,
			Description: fmt.Sprintf("User '%s' shell changed from '%s' to '%s'", newer.Name, older.Shell, newer.Shell),
			OldValue:    older.Shell,
			NewValue:    newer.Shell,
		})
	}

	return changes
}

// compareGroups compares group lists between snapshots
func (m *Manager) compareGroups(older, newer []dsaudit.Group) []Change {
	var changes []Change

	olderMap := make(map[string]dsaudit.Group)
	for _, g := range older {
		olderMap[g.Name] = g
	}

	newerMap := make(map[string]dsaudit.Group)
	for _, g := range newer {
		newerMap[g.Name] = g
	}

	// Check admin/wheel group membership changes
	for _, name := range []string{"admin", "wheel"} {
		oldGroup, oldExists := olderMap[name]
		newGroup, newExists := newerMap[name]

		if !oldExists || !newExists {
			continue
		}

		oldMembers := make(map[string]bool)
		for _, m := range oldGroup.Members {
			oldMembers[m] = true
		}

		// Find new members
		for _, member := range newGroup.Members {
			if !oldMembers[member] {
				changes = append(changes, Change{
					Type:        "group",
					Action:      "modified",
					Severity:    "critical",
					Name:        name,
					Description: fmt.Sprintf("User '%s' added to '%s' group", member, name),
					Details: map[string]interface{}{
						"added_member": member,
					},
				})
			}
		}

		// Find removed members
		newMembers := make(map[string]bool)
		for _, m := range newGroup.Members {
			newMembers[m] = true
		}
		for _, member := range oldGroup.Members {
			if !newMembers[member] {
				changes = append(changes, Change{
					Type:        "group",
					Action:      "modified",
					Severity:    "medium",
					Name:        name,
					Description: fmt.Sprintf("User '%s' removed from '%s' group", member, name),
					Details: map[string]interface{}{
						"removed_member": member,
					},
				})
			}
		}
	}

	return changes
}

// compareLaunchItems compares launch items between snapshots
func (m *Manager) compareLaunchItems(older, newer []LaunchItem) []Change {
	var changes []Change

	olderMap := make(map[string]LaunchItem)
	for _, item := range older {
		olderMap[item.Path] = item
	}

	newerMap := make(map[string]LaunchItem)
	for _, item := range newer {
		newerMap[item.Path] = item
	}

	// Find new launch items
	for path, newItem := range newerMap {
		if _, exists := olderMap[path]; !exists {
			severity := "high"
			if newItem.Type == "daemon" {
				severity = "critical"
			}
			changes = append(changes, Change{
				Type:        "launch_item",
				Action:      "added",
				Severity:    severity,
				Path:        path,
				Name:        newItem.Label,
				Description: fmt.Sprintf("New %s '%s' added", newItem.Type, newItem.Label),
				NewValue:    newItem,
			})
		}
	}

	// Find removed launch items
	for path, oldItem := range olderMap {
		if _, exists := newerMap[path]; !exists {
			changes = append(changes, Change{
				Type:        "launch_item",
				Action:      "removed",
				Severity:    "medium",
				Path:        path,
				Name:        oldItem.Label,
				Description: fmt.Sprintf("%s '%s' removed", oldItem.Type, oldItem.Label),
				OldValue:    oldItem,
			})
		}
	}

	// Find modified launch items
	for path, newItem := range newerMap {
		if oldItem, exists := olderMap[path]; exists {
			if newItem.Hash != oldItem.Hash {
				changes = append(changes, Change{
					Type:        "launch_item",
					Action:      "modified",
					Severity:    "high",
					Path:        path,
					Name:        newItem.Label,
					Description: fmt.Sprintf("%s '%s' was modified", newItem.Type, newItem.Label),
					OldValue:    oldItem,
					NewValue:    newItem,
				})
			}
		}
	}

	return changes
}

// compareSystemConfig compares system configuration between snapshots
func (m *Manager) compareSystemConfig(older, newer SystemConfig) []Change {
	var changes []Change

	// SIP status
	if older.SIPEnabled != newer.SIPEnabled {
		severity := "critical"
		action := "enabled"
		if !newer.SIPEnabled {
			action = "disabled"
		}
		changes = append(changes, Change{
			Type:        "system_config",
			Action:      "modified",
			Severity:    severity,
			Name:        "SIP",
			Description: fmt.Sprintf("System Integrity Protection was %s", action),
			OldValue:    older.SIPEnabled,
			NewValue:    newer.SIPEnabled,
		})
	}

	// Firewall status
	if older.FirewallEnabled != newer.FirewallEnabled {
		action := "enabled"
		if !newer.FirewallEnabled {
			action = "disabled"
		}
		changes = append(changes, Change{
			Type:        "system_config",
			Action:      "modified",
			Severity:    "high",
			Name:        "Firewall",
			Description: fmt.Sprintf("Firewall was %s", action),
			OldValue:    older.FirewallEnabled,
			NewValue:    newer.FirewallEnabled,
		})
	}

	// Remote login
	if older.RemoteLogin != newer.RemoteLogin {
		action := "enabled"
		severity := "high"
		if !newer.RemoteLogin {
			action = "disabled"
			severity = "medium"
		}
		changes = append(changes, Change{
			Type:        "system_config",
			Action:      "modified",
			Severity:    severity,
			Name:        "Remote Login",
			Description: fmt.Sprintf("Remote Login (SSH) was %s", action),
			OldValue:    older.RemoteLogin,
			NewValue:    newer.RemoteLogin,
		})
	}

	return changes
}

// enumerateLaunchItems finds all launch daemons and agents
func (m *Manager) enumerateLaunchItems() []LaunchItem {
	var items []LaunchItem

	// Launch Daemons
	daemonDirs := []string{
		"/Library/LaunchDaemons",
		"/System/Library/LaunchDaemons",
	}

	for _, dir := range daemonDirs {
		dirItems := m.scanLaunchDir(dir, "daemon")
		items = append(items, dirItems...)
	}

	// Launch Agents
	agentDirs := []string{
		"/Library/LaunchAgents",
	}

	// User launch agents
	if homeDir, err := os.UserHomeDir(); err == nil {
		agentDirs = append(agentDirs, filepath.Join(homeDir, "Library/LaunchAgents"))
	}

	for _, dir := range agentDirs {
		dirItems := m.scanLaunchDir(dir, "agent")
		items = append(items, dirItems...)
	}

	return items
}

// scanLaunchDir scans a directory for launch items
func (m *Manager) scanLaunchDir(dir string, itemType string) []LaunchItem {
	var items []LaunchItem

	files, err := os.ReadDir(dir)
	if err != nil {
		return items
	}

	for _, file := range files {
		if !strings.HasSuffix(file.Name(), ".plist") {
			continue
		}

		path := filepath.Join(dir, file.Name())
		item := LaunchItem{
			Path: path,
			Type: itemType,
		}

		// Read and hash the file
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}

		hash := sha256.Sum256(data)
		item.Hash = hex.EncodeToString(hash[:])

		// Extract label from filename (basic approach)
		item.Label = strings.TrimSuffix(file.Name(), ".plist")

		items = append(items, item)
	}

	return items
}

// getSystemConfig retrieves security-relevant system configuration
func (m *Manager) getSystemConfig() SystemConfig {
	config := SystemConfig{
		SSHConfig: make(map[string]string),
	}

	// These would typically use system commands to check status
	// Simplified for now
	config.SIPEnabled = true      // Would check via csrutil status
	config.FirewallEnabled = true // Would check via socketfilterfw
	config.FileVaultEnabled = false
	config.RemoteLogin = false
	config.RemoteDesktop = false

	return config
}

// computeSnapshotHash creates a hash of the snapshot for integrity
func (m *Manager) computeSnapshotHash(snapshot *Snapshot) string {
	// Create a deterministic representation
	data := fmt.Sprintf("%v|%v|%v|%v",
		len(snapshot.Users),
		len(snapshot.Groups),
		len(snapshot.LaunchItems),
		snapshot.SystemConfig.SIPEnabled,
	)
	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:16])
}

// generateSummary creates a human-readable summary of changes
func (m *Manager) generateSummary(result *DiffResult) string {
	var parts []string

	if result.CriticalChanges > 0 {
		parts = append(parts, fmt.Sprintf("%d critical", result.CriticalChanges))
	}
	if result.HighChanges > 0 {
		parts = append(parts, fmt.Sprintf("%d high", result.HighChanges))
	}

	if len(parts) == 0 {
		return fmt.Sprintf("%d changes detected", result.TotalChanges)
	}

	return fmt.Sprintf("%d changes detected (%s severity)", result.TotalChanges, strings.Join(parts, ", "))
}

// generateID creates a unique snapshot ID
func generateID() string {
	data := fmt.Sprintf("%d", time.Now().UnixNano())
	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:4])
}

// GetLatestSnapshot returns the most recent snapshot
func (m *Manager) GetLatestSnapshot() *Snapshot {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.latestSnapshot
}

// CompareWithLatest compares the current state with the latest snapshot
func (m *Manager) CompareWithLatest() (*DiffResult, error) {
	m.mu.RLock()
	latest := m.latestSnapshot
	m.mu.RUnlock()

	if latest == nil {
		return nil, fmt.Errorf("no previous snapshot available")
	}

	// Take new snapshot
	current, err := m.TakeSnapshot()
	if err != nil {
		return nil, err
	}

	return m.Compare(latest, current)
}

// DeleteSnapshot removes a snapshot file
func (m *Manager) DeleteSnapshot(id string) error {
	files, err := os.ReadDir(m.snapshotDir)
	if err != nil {
		return err
	}

	for _, file := range files {
		if strings.Contains(file.Name(), id) {
			return os.Remove(filepath.Join(m.snapshotDir, file.Name()))
		}
	}

	return fmt.Errorf("snapshot not found: %s", id)
}

// PruneOldSnapshots removes snapshots older than the given duration
func (m *Manager) PruneOldSnapshots(maxAge time.Duration) (int, error) {
	snapshots, err := m.ListSnapshots()
	if err != nil {
		return 0, err
	}

	cutoff := time.Now().Add(-maxAge)
	pruned := 0

	for _, snap := range snapshots {
		if snap.Timestamp.Before(cutoff) {
			if err := os.Remove(snap.FilePath); err == nil {
				pruned++
			}
		}
	}

	return pruned, nil
}
