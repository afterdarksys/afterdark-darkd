// Package auth provides user authorization for enhanced security features on macOS
//
// This module:
// - Manages authorization levels for different features
// - Prompts users for permission when needed
// - Integrates with macOS Security framework
// - Tracks authorization state
// - Supports admin/root elevation when required
//
// Authorization Levels:
// - Level 0: Basic (default) - read-only system info, no secrets
// - Level 1: Enhanced - can read keychain metadata, audit logs
// - Level 2: Full Access - can read secrets, modify system (requires explicit user auth)
// - Level 3: Admin - requires root privileges
//
// Build: Part of osx-security plugin for afterdark-darkd
package auth

import (
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"strings"
	"sync"
	"time"
)

// AuthLevel represents the authorization level
type AuthLevel int

const (
	// LevelBasic - read-only access to public system info
	LevelBasic AuthLevel = 0
	// LevelEnhanced - read keychain metadata, audit logs
	LevelEnhanced AuthLevel = 1
	// LevelFullAccess - read secrets, requires user authorization
	LevelFullAccess AuthLevel = 2
	// LevelAdmin - requires root/admin privileges
	LevelAdmin AuthLevel = 3
)

// Feature represents a security feature requiring authorization
type Feature string

const (
	FeatureDSAudit         Feature = "ds_audit"          // Directory Services auditing
	FeatureDSMonitor       Feature = "ds_monitor"        // DS change monitoring
	FeatureKeychainList    Feature = "keychain_list"     // List keychain items
	FeatureKeychainRead    Feature = "keychain_read"     // Read keychain secrets
	FeatureKeychainAnalyze Feature = "keychain_analyze"  // Analyze keychain security
	FeatureFSMonitor       Feature = "fs_monitor"        // File system monitoring
	FeatureSnapshot        Feature = "snapshot"          // Take security snapshots
	FeatureSnapshotCompare Feature = "snapshot_compare"  // Compare snapshots
	FeatureSystemConfig    Feature = "system_config"     // Read system config
	FeatureSystemModify    Feature = "system_modify"     // Modify system settings
	FeatureLaunchItemAudit Feature = "launch_item_audit" // Audit launch items
)

// FeatureRequirements maps features to their required authorization level
var FeatureRequirements = map[Feature]AuthLevel{
	FeatureDSAudit:         LevelBasic,
	FeatureDSMonitor:       LevelEnhanced,
	FeatureKeychainList:    LevelBasic,
	FeatureKeychainRead:    LevelFullAccess,
	FeatureKeychainAnalyze: LevelEnhanced,
	FeatureFSMonitor:       LevelEnhanced,
	FeatureSnapshot:        LevelEnhanced,
	FeatureSnapshotCompare: LevelBasic,
	FeatureSystemConfig:    LevelBasic,
	FeatureSystemModify:    LevelAdmin,
	FeatureLaunchItemAudit: LevelBasic,
}

// Authorization represents the current authorization state
type Authorization struct {
	Level           AuthLevel              `json:"level"`
	GrantedAt       time.Time              `json:"granted_at"`
	ExpiresAt       time.Time              `json:"expires_at,omitempty"`
	User            string                 `json:"user"`
	IsRoot          bool                   `json:"is_root"`
	IsAdmin         bool                   `json:"is_admin"`
	GrantedFeatures []Feature              `json:"granted_features"`
	Metadata        map[string]interface{} `json:"metadata,omitempty"`
}

// Manager handles authorization for the plugin
type Manager struct {
	mu            sync.RWMutex
	currentAuth   *Authorization
	authCallbacks []AuthCallback
	interactive   bool // Whether we can prompt the user
}

// AuthCallback is called when authorization changes
type AuthCallback func(Authorization)

// NewManager creates a new authorization manager
func NewManager() *Manager {
	m := &Manager{
		authCallbacks: make([]AuthCallback, 0),
		interactive:   true,
	}

	// Initialize with basic level
	m.currentAuth = m.detectCurrentAuth()

	return m
}

// detectCurrentAuth determines the current authorization based on environment
func (m *Manager) detectCurrentAuth() *Authorization {
	auth := &Authorization{
		Level:           LevelBasic,
		GrantedAt:       time.Now(),
		GrantedFeatures: make([]Feature, 0),
		Metadata:        make(map[string]interface{}),
	}

	// Get current user
	if u, err := user.Current(); err == nil {
		auth.User = u.Username
		auth.Metadata["uid"] = u.Uid
		auth.Metadata["gid"] = u.Gid
		auth.Metadata["home"] = u.HomeDir

		// Check if root
		if u.Uid == "0" {
			auth.IsRoot = true
			auth.Level = LevelAdmin
		}
	}

	// Check if user is admin (in admin group)
	auth.IsAdmin = m.checkAdminMembership()

	// Grant features based on level
	for feature, required := range FeatureRequirements {
		if required <= auth.Level {
			auth.GrantedFeatures = append(auth.GrantedFeatures, feature)
		}
	}

	return auth
}

// checkAdminMembership checks if current user is in admin group
// Uses native os/user package instead of exec.Command
func (m *Manager) checkAdminMembership() bool {
	currentUser, err := user.Current()
	if err != nil {
		return false
	}

	groupIDs, err := currentUser.GroupIds()
	if err != nil {
		return false
	}

	for _, gid := range groupIDs {
		group, err := user.LookupGroupId(gid)
		if err != nil {
			continue
		}
		if group.Name == "admin" || group.Name == "wheel" {
			return true
		}
	}
	return false
}

// GetCurrentAuth returns the current authorization state
func (m *Manager) GetCurrentAuth() *Authorization {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.currentAuth
}

// IsAuthorized checks if a feature is authorized
func (m *Manager) IsAuthorized(feature Feature) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()

	required, exists := FeatureRequirements[feature]
	if !exists {
		return false
	}

	return m.currentAuth.Level >= required
}

// RequireAuth ensures a feature is authorized, prompting if necessary
func (m *Manager) RequireAuth(feature Feature) error {
	if m.IsAuthorized(feature) {
		return nil
	}

	required := FeatureRequirements[feature]
	return fmt.Errorf("feature '%s' requires authorization level %d, current level is %d",
		feature, required, m.currentAuth.Level)
}

// RequestElevation requests elevated privileges
func (m *Manager) RequestElevation(targetLevel AuthLevel, reason string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.currentAuth.Level >= targetLevel {
		return nil // Already at required level
	}

	switch targetLevel {
	case LevelEnhanced:
		return m.requestEnhancedAccess(reason)
	case LevelFullAccess:
		return m.requestFullAccess(reason)
	case LevelAdmin:
		return m.requestAdminAccess(reason)
	}

	return fmt.Errorf("unknown authorization level: %d", targetLevel)
}

// requestEnhancedAccess requests enhanced access level
func (m *Manager) requestEnhancedAccess(reason string) error {
	if !m.interactive {
		return fmt.Errorf("enhanced access requires user interaction")
	}

	// For enhanced access, we just need user confirmation
	// In a real implementation, this would use macOS authorization services
	m.currentAuth.Level = LevelEnhanced
	m.currentAuth.GrantedAt = time.Now()
	m.currentAuth.ExpiresAt = time.Now().Add(1 * time.Hour)

	// Update granted features
	m.updateGrantedFeatures()
	m.notifyCallbacks()

	return nil
}

// requestFullAccess requests full access level (reads secrets)
func (m *Manager) requestFullAccess(reason string) error {
	if !m.interactive {
		return fmt.Errorf("full access requires user interaction")
	}

	// This would use macOS Security framework to request authorization
	// Using osascript as a placeholder for demonstration
	script := fmt.Sprintf(`display dialog "AfterDark Security requests access to read keychain data.\n\nReason: %s" buttons {"Deny", "Allow"} default button "Allow" with icon caution`, reason)

	cmd := exec.Command("osascript", "-e", script)
	out, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("authorization denied or failed: %w", err)
	}

	if !strings.Contains(string(out), "Allow") {
		return fmt.Errorf("user denied authorization")
	}

	m.currentAuth.Level = LevelFullAccess
	m.currentAuth.GrantedAt = time.Now()
	m.currentAuth.ExpiresAt = time.Now().Add(30 * time.Minute)

	m.updateGrantedFeatures()
	m.notifyCallbacks()

	return nil
}

// requestAdminAccess requests admin/root access
func (m *Manager) requestAdminAccess(reason string) error {
	if m.currentAuth.IsRoot {
		m.currentAuth.Level = LevelAdmin
		return nil
	}

	if !m.currentAuth.IsAdmin {
		return fmt.Errorf("admin privileges require admin group membership")
	}

	// Use AuthorizationExecuteWithPrivileges equivalent
	// This is a placeholder - real implementation would use Security framework
	script := fmt.Sprintf(`do shell script "echo authorized" with administrator privileges with prompt "AfterDark Security requires administrator privileges.\n\nReason: %s"`, reason)

	cmd := exec.Command("osascript", "-e", script)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("admin authorization failed: %w", err)
	}

	m.currentAuth.Level = LevelAdmin
	m.currentAuth.GrantedAt = time.Now()
	m.currentAuth.ExpiresAt = time.Now().Add(15 * time.Minute)

	m.updateGrantedFeatures()
	m.notifyCallbacks()

	return nil
}

// updateGrantedFeatures updates the list of granted features based on current level
func (m *Manager) updateGrantedFeatures() {
	m.currentAuth.GrantedFeatures = make([]Feature, 0)
	for feature, required := range FeatureRequirements {
		if required <= m.currentAuth.Level {
			m.currentAuth.GrantedFeatures = append(m.currentAuth.GrantedFeatures, feature)
		}
	}
}

// notifyCallbacks notifies all registered callbacks of auth change
func (m *Manager) notifyCallbacks() {
	for _, cb := range m.authCallbacks {
		cb(*m.currentAuth)
	}
}

// OnAuthChange registers a callback for authorization changes
func (m *Manager) OnAuthChange(callback AuthCallback) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.authCallbacks = append(m.authCallbacks, callback)
}

// SetInteractive sets whether the manager can prompt the user
func (m *Manager) SetInteractive(interactive bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.interactive = interactive
}

// RevokeElevation revokes elevated privileges
func (m *Manager) RevokeElevation() {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Reset to basic level (or admin if root)
	if m.currentAuth.IsRoot {
		m.currentAuth.Level = LevelAdmin
	} else {
		m.currentAuth.Level = LevelBasic
	}
	m.currentAuth.ExpiresAt = time.Time{}
	m.updateGrantedFeatures()
	m.notifyCallbacks()
}

// CheckExpiration checks if authorization has expired and revokes if necessary
func (m *Manager) CheckExpiration() bool {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.currentAuth.ExpiresAt.IsZero() {
		return false
	}

	if time.Now().After(m.currentAuth.ExpiresAt) {
		// Expired - revoke to basic
		if m.currentAuth.IsRoot {
			m.currentAuth.Level = LevelAdmin
		} else {
			m.currentAuth.Level = LevelBasic
		}
		m.currentAuth.ExpiresAt = time.Time{}
		m.updateGrantedFeatures()
		m.notifyCallbacks()
		return true
	}

	return false
}

// GetRequiredLevel returns the required level for a feature
func GetRequiredLevel(feature Feature) AuthLevel {
	if level, exists := FeatureRequirements[feature]; exists {
		return level
	}
	return LevelAdmin // Default to highest if unknown
}

// IsRunningAsRoot checks if the process is running as root
func IsRunningAsRoot() bool {
	return os.Getuid() == 0
}

// CanElevate checks if the current user can elevate privileges
func (m *Manager) CanElevate() bool {
	return m.currentAuth.IsAdmin || m.currentAuth.IsRoot
}

// AuthLevelString returns a human-readable string for an auth level
func AuthLevelString(level AuthLevel) string {
	switch level {
	case LevelBasic:
		return "Basic (read-only)"
	case LevelEnhanced:
		return "Enhanced (metadata access)"
	case LevelFullAccess:
		return "Full Access (secrets readable)"
	case LevelAdmin:
		return "Admin (system modifications)"
	default:
		return "Unknown"
	}
}

// RequiredPrivileges describes what privileges are needed for a feature
type RequiredPrivileges struct {
	Feature     Feature   `json:"feature"`
	Level       AuthLevel `json:"level"`
	Description string    `json:"description"`
	NeedsRoot   bool      `json:"needs_root"`
	NeedsAdmin  bool      `json:"needs_admin"`
}

// GetFeaturePrivileges returns privilege requirements for all features
func GetFeaturePrivileges() []RequiredPrivileges {
	return []RequiredPrivileges{
		{FeatureDSAudit, LevelBasic, "Audit user accounts and groups", false, false},
		{FeatureDSMonitor, LevelEnhanced, "Monitor Directory Services for changes", false, false},
		{FeatureKeychainList, LevelBasic, "List keychain items (no secrets)", false, false},
		{FeatureKeychainRead, LevelFullAccess, "Read keychain secrets", false, false},
		{FeatureKeychainAnalyze, LevelEnhanced, "Analyze keychain for security issues", false, false},
		{FeatureFSMonitor, LevelEnhanced, "Monitor security-sensitive files", false, true},
		{FeatureSnapshot, LevelEnhanced, "Take security state snapshots", false, false},
		{FeatureSnapshotCompare, LevelBasic, "Compare security snapshots", false, false},
		{FeatureSystemConfig, LevelBasic, "Read system security configuration", false, false},
		{FeatureSystemModify, LevelAdmin, "Modify system security settings", true, true},
		{FeatureLaunchItemAudit, LevelBasic, "Audit launch daemons and agents", false, false},
	}
}

// VerifyKeychain attempts to verify access to keychain
func (m *Manager) VerifyKeychainAccess() error {
	// Try to list keychains - this should work at any level
	cmd := exec.Command("/usr/bin/security", "list-keychains")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("cannot access keychain: %w", err)
	}
	return nil
}

// VerifyDSAccess verifies access to Directory Services
func (m *Manager) VerifyDSAccess() error {
	cmd := exec.Command("/usr/bin/dscl", ".", "-list", "/Users")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("cannot access Directory Services: %w", err)
	}
	return nil
}
