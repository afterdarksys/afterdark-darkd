// macOS Security Plugin for afterdark-darkd
//
// Provides comprehensive macOS security auditing and monitoring:
// - Directory Services (user/group) auditing and change detection
// - Keychain analysis and anomaly detection
// - File system monitoring for security-sensitive paths
// - Security state snapshotting and comparison
// - User authorization for enhanced features
//
// Can run standalone or as a darkd gRPC plugin for EDR integration.
//
// Build: go build -o osx-security .
// Install: cp osx-security /var/lib/afterdark-darkd/plugins/
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/afterdarksys/afterdark-darkd/plugins/osx-security/auth"
	"github.com/afterdarksys/afterdark-darkd/plugins/osx-security/dsaudit"
	"github.com/afterdarksys/afterdark-darkd/plugins/osx-security/fsmonitor"
	"github.com/afterdarksys/afterdark-darkd/plugins/osx-security/keywatch"
	"github.com/afterdarksys/afterdark-darkd/plugins/osx-security/snapshot"
)

const (
	PluginName    = "osx-security"
	PluginVersion = "1.0.0"
)

// PluginState represents plugin state
type PluginState int

const (
	PluginStateReady PluginState = iota
	PluginStateRunning
	PluginStateStopped
)

// OSXSecurityPlugin implements macOS security auditing
type OSXSecurityPlugin struct {
	state   PluginState
	message string
	config  map[string]interface{}

	mu            sync.RWMutex
	dsAuditor     *dsaudit.Auditor
	keyAnalyzer   *keywatch.Analyzer
	fsMonitor     *fsmonitor.Monitor
	snapshotMgr   *snapshot.Manager
	authMgr       *auth.Manager

	// Configuration
	snapshotDir      string
	monitorConfig    fsmonitor.MonitorConfig
	autoSnapshot     bool
	snapshotInterval time.Duration

	// State
	running         bool
	lastDSAudit     *dsaudit.AuditResult
	lastKeyAnalysis *keywatch.AnalysisResult
	eventBuffer     []fsmonitor.Event
	eventBufferSize int

	// Channels
	stopCh  chan struct{}
	eventCh chan fsmonitor.Event
}

// PluginInfo contains metadata about the plugin
type PluginInfo struct {
	Name         string   `json:"name"`
	Version      string   `json:"version"`
	Type         string   `json:"type"`
	Description  string   `json:"description"`
	Author       string   `json:"author"`
	License      string   `json:"license"`
	Capabilities []string `json:"capabilities"`
}

func (p *OSXSecurityPlugin) Info() PluginInfo {
	return PluginInfo{
		Name:        PluginName,
		Version:     PluginVersion,
		Type:        "service",
		Description: "macOS security auditing and monitoring (Directory Services, Keychain, file system)",
		Author:      "After Dark Systems, LLC",
		License:     "MIT",
		Capabilities: []string{
			"ds_audit", "ds_monitor",
			"keychain_list", "keychain_analyze",
			"fs_monitor",
			"snapshot", "snapshot_compare",
			"user_auth",
		},
	}
}

func (p *OSXSecurityPlugin) Configure(config map[string]interface{}) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.config = config

	// Parse configuration
	if dir, ok := config["snapshot_dir"].(string); ok {
		p.snapshotDir = dir
	} else {
		// Default snapshot directory
		homeDir, _ := os.UserHomeDir()
		p.snapshotDir = filepath.Join(homeDir, ".afterdark", "osx-security", "snapshots")
	}

	if auto, ok := config["auto_snapshot"].(bool); ok {
		p.autoSnapshot = auto
	}

	if interval, ok := config["snapshot_interval_minutes"].(float64); ok {
		p.snapshotInterval = time.Duration(interval) * time.Minute
	} else {
		p.snapshotInterval = 60 * time.Minute // Default 1 hour
	}

	if bufSize, ok := config["event_buffer_size"].(float64); ok {
		p.eventBufferSize = int(bufSize)
	} else {
		p.eventBufferSize = 1000
	}

	// Initialize components
	p.dsAuditor = dsaudit.NewAuditor()
	p.keyAnalyzer = keywatch.NewAnalyzer()
	p.authMgr = auth.NewManager()
	p.eventBuffer = make([]fsmonitor.Event, 0, p.eventBufferSize)
	p.eventCh = make(chan fsmonitor.Event, 100)

	// Initialize snapshot manager
	var err error
	p.snapshotMgr, err = snapshot.NewManager(p.snapshotDir)
	if err != nil {
		return fmt.Errorf("failed to initialize snapshot manager: %w", err)
	}

	// Initialize FS monitor with default config
	p.monitorConfig = fsmonitor.DefaultConfig()
	if monitorCfg, ok := config["monitor"].(map[string]interface{}); ok {
		if ds, ok := monitorCfg["directory_services"].(bool); ok {
			p.monitorConfig.MonitorDirectoryServices = ds
		}
		if kc, ok := monitorCfg["keychain"].(bool); ok {
			p.monitorConfig.MonitorUserKeychain = kc
		}
	}

	p.state = PluginStateReady
	p.message = "configured"
	return nil
}

func (p *OSXSecurityPlugin) Start(ctx context.Context) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.running {
		return fmt.Errorf("plugin already running")
	}

	// Start FS monitor
	var err error
	p.fsMonitor, err = fsmonitor.NewMonitor(p.monitorConfig, p.handleFSEvent)
	if err != nil {
		return fmt.Errorf("failed to create FS monitor: %w", err)
	}

	if err := p.fsMonitor.Start(); err != nil {
		return fmt.Errorf("failed to start FS monitor: %w", err)
	}

	p.stopCh = make(chan struct{})
	p.running = true

	// Start background tasks
	go p.backgroundLoop()

	// Take initial snapshot if configured
	if p.autoSnapshot {
		go func() {
			if snap, err := p.snapshotMgr.TakeSnapshot(); err == nil {
				p.snapshotMgr.SaveSnapshot(snap)
			}
		}()
	}

	p.state = PluginStateRunning
	p.message = "monitoring active"
	return nil
}

func (p *OSXSecurityPlugin) Stop(ctx context.Context) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if !p.running {
		return nil
	}

	// Signal stop
	close(p.stopCh)

	// Stop FS monitor
	if p.fsMonitor != nil {
		p.fsMonitor.Stop()
	}

	p.running = false
	p.state = PluginStateStopped
	p.message = "stopped"

	return nil
}

func (p *OSXSecurityPlugin) Execute(ctx context.Context, action string, params map[string]interface{}) (map[string]interface{}, error) {
	switch action {
	// Directory Services actions
	case "ds_audit":
		return p.executeDSAudit(ctx, params)
	case "ds_get_user":
		return p.executeGetUser(ctx, params)
	case "ds_get_admins":
		return p.executeGetAdmins(ctx, params)
	case "ds_get_hidden":
		return p.executeGetHidden(ctx, params)

	// Keychain actions
	case "keychain_analyze":
		return p.executeKeychainAnalyze(ctx, params)
	case "keychain_search":
		return p.executeKeychainSearch(ctx, params)
	case "keychain_duplicates":
		return p.executeKeychainDuplicates(ctx, params)

	// Snapshot actions
	case "snapshot_take":
		return p.executeSnapshotTake(ctx, params)
	case "snapshot_list":
		return p.executeSnapshotList(ctx, params)
	case "snapshot_compare":
		return p.executeSnapshotCompare(ctx, params)
	case "snapshot_diff_latest":
		return p.executeSnapshotDiffLatest(ctx, params)

	// Monitor actions
	case "monitor_status":
		return p.executeMonitorStatus(ctx, params)
	case "monitor_events":
		return p.executeMonitorEvents(ctx, params)

	// Authorization actions
	case "auth_status":
		return p.executeAuthStatus(ctx, params)
	case "auth_elevate":
		return p.executeAuthElevate(ctx, params)
	case "auth_revoke":
		return p.executeAuthRevoke(ctx, params)

	// Combined/summary actions
	case "full_audit":
		return p.executeFullAudit(ctx, params)
	case "status":
		return p.executeStatus(ctx, params)

	default:
		return nil, fmt.Errorf("unknown action: %s", action)
	}
}

// Action implementations

func (p *OSXSecurityPlugin) executeDSAudit(ctx context.Context, params map[string]interface{}) (map[string]interface{}, error) {
	result, err := p.dsAuditor.Audit()
	if err != nil {
		return nil, err
	}

	p.mu.Lock()
	p.lastDSAudit = result
	p.mu.Unlock()

	return map[string]interface{}{
		"timestamp":        result.Timestamp,
		"macos_version":    result.MacOSVersion,
		"total_users":      result.TotalUsers,
		"admin_users":      result.AdminUsers,
		"hidden_users":     result.HiddenUsers,
		"system_accounts":  result.SystemAccounts,
		"total_groups":     result.TotalGroups,
		"findings":         result.Findings,
		"users":            result.Users,
		"groups":           result.Groups,
	}, nil
}

func (p *OSXSecurityPlugin) executeGetUser(ctx context.Context, params map[string]interface{}) (map[string]interface{}, error) {
	username, ok := params["username"].(string)
	if !ok {
		return nil, fmt.Errorf("username parameter required")
	}

	user, err := p.dsAuditor.GetUser(username)
	if err != nil {
		return nil, err
	}

	return map[string]interface{}{
		"user": user,
	}, nil
}

func (p *OSXSecurityPlugin) executeGetAdmins(ctx context.Context, params map[string]interface{}) (map[string]interface{}, error) {
	admins, err := p.dsAuditor.GetAdminUsers()
	if err != nil {
		return nil, err
	}

	return map[string]interface{}{
		"admin_users": admins,
		"count":       len(admins),
	}, nil
}

func (p *OSXSecurityPlugin) executeGetHidden(ctx context.Context, params map[string]interface{}) (map[string]interface{}, error) {
	hidden, err := p.dsAuditor.GetHiddenUsers()
	if err != nil {
		return nil, err
	}

	return map[string]interface{}{
		"hidden_users": hidden,
		"count":        len(hidden),
	}, nil
}

func (p *OSXSecurityPlugin) executeKeychainAnalyze(ctx context.Context, params map[string]interface{}) (map[string]interface{}, error) {
	// Check authorization
	if err := p.authMgr.RequireAuth(auth.FeatureKeychainAnalyze); err != nil {
		return map[string]interface{}{
			"error":          err.Error(),
			"requires_auth":  true,
			"current_level":  p.authMgr.GetCurrentAuth().Level,
			"required_level": auth.LevelEnhanced,
		}, nil
	}

	result, err := p.keyAnalyzer.Analyze()
	if err != nil {
		return nil, err
	}

	p.mu.Lock()
	p.lastKeyAnalysis = result
	p.mu.Unlock()

	return map[string]interface{}{
		"timestamp":          result.Timestamp,
		"keychains":          result.KeychainsAnalyzed,
		"total_items":        result.TotalItems,
		"generic_passwords":  result.GenericPasswords,
		"internet_passwords": result.InternetPasswords,
		"certificates":       result.Certificates,
		"duplicates":         result.Duplicates,
		"findings":           result.Findings,
		"requires_auth":      result.RequiresAuth,
	}, nil
}

func (p *OSXSecurityPlugin) executeKeychainSearch(ctx context.Context, params map[string]interface{}) (map[string]interface{}, error) {
	query, ok := params["query"].(string)
	if !ok {
		return nil, fmt.Errorf("query parameter required")
	}

	items, err := p.keyAnalyzer.SearchItems(query)
	if err != nil {
		return nil, err
	}

	return map[string]interface{}{
		"items": items,
		"count": len(items),
	}, nil
}

func (p *OSXSecurityPlugin) executeKeychainDuplicates(ctx context.Context, params map[string]interface{}) (map[string]interface{}, error) {
	result, err := p.keyAnalyzer.Analyze()
	if err != nil {
		return nil, err
	}

	return map[string]interface{}{
		"duplicates": result.Duplicates,
		"count":      len(result.Duplicates),
	}, nil
}

func (p *OSXSecurityPlugin) executeSnapshotTake(ctx context.Context, params map[string]interface{}) (map[string]interface{}, error) {
	snap, err := p.snapshotMgr.TakeSnapshot()
	if err != nil {
		return nil, err
	}

	// Save by default unless explicitly disabled
	if save, ok := params["save"].(bool); !ok || save {
		if err := p.snapshotMgr.SaveSnapshot(snap); err != nil {
			return nil, fmt.Errorf("snapshot taken but failed to save: %w", err)
		}
	}

	return map[string]interface{}{
		"snapshot_id":  snap.ID,
		"timestamp":    snap.Timestamp,
		"hash":         snap.Hash,
		"users":        len(snap.Users),
		"groups":       len(snap.Groups),
		"launch_items": len(snap.LaunchItems),
	}, nil
}

func (p *OSXSecurityPlugin) executeSnapshotList(ctx context.Context, params map[string]interface{}) (map[string]interface{}, error) {
	snapshots, err := p.snapshotMgr.ListSnapshots()
	if err != nil {
		return nil, err
	}

	return map[string]interface{}{
		"snapshots": snapshots,
		"count":     len(snapshots),
	}, nil
}

func (p *OSXSecurityPlugin) executeSnapshotCompare(ctx context.Context, params map[string]interface{}) (map[string]interface{}, error) {
	olderID, ok1 := params["older"].(string)
	newerID, ok2 := params["newer"].(string)
	if !ok1 || !ok2 {
		return nil, fmt.Errorf("older and newer snapshot IDs required")
	}

	older, err := p.snapshotMgr.LoadSnapshot(olderID)
	if err != nil {
		return nil, fmt.Errorf("failed to load older snapshot: %w", err)
	}

	newer, err := p.snapshotMgr.LoadSnapshot(newerID)
	if err != nil {
		return nil, fmt.Errorf("failed to load newer snapshot: %w", err)
	}

	diff, err := p.snapshotMgr.Compare(older, newer)
	if err != nil {
		return nil, err
	}

	return map[string]interface{}{
		"older_snapshot":   diff.OlderSnapshot,
		"newer_snapshot":   diff.NewerSnapshot,
		"time_delta":       diff.TimeDelta.String(),
		"total_changes":    diff.TotalChanges,
		"critical_changes": diff.CriticalChanges,
		"high_changes":     diff.HighChanges,
		"changes":          diff.Changes,
		"summary":          diff.Summary,
	}, nil
}

func (p *OSXSecurityPlugin) executeSnapshotDiffLatest(ctx context.Context, params map[string]interface{}) (map[string]interface{}, error) {
	diff, err := p.snapshotMgr.CompareWithLatest()
	if err != nil {
		return nil, err
	}

	return map[string]interface{}{
		"total_changes":    diff.TotalChanges,
		"critical_changes": diff.CriticalChanges,
		"high_changes":     diff.HighChanges,
		"changes":          diff.Changes,
		"summary":          diff.Summary,
	}, nil
}

func (p *OSXSecurityPlugin) executeMonitorStatus(ctx context.Context, params map[string]interface{}) (map[string]interface{}, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	result := map[string]interface{}{
		"running":           p.running,
		"event_buffer_size": len(p.eventBuffer),
	}

	if p.fsMonitor != nil {
		stats := p.fsMonitor.Stats()
		result["monitor_stats"] = stats
		result["monitored_paths"] = p.fsMonitor.GetMonitoredPaths()
	}

	return result, nil
}

func (p *OSXSecurityPlugin) executeMonitorEvents(ctx context.Context, params map[string]interface{}) (map[string]interface{}, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	limit := 100
	if l, ok := params["limit"].(float64); ok {
		limit = int(l)
	}

	events := p.eventBuffer
	if len(events) > limit {
		events = events[len(events)-limit:]
	}

	return map[string]interface{}{
		"events": events,
		"count":  len(events),
		"total":  len(p.eventBuffer),
	}, nil
}

func (p *OSXSecurityPlugin) executeAuthStatus(ctx context.Context, params map[string]interface{}) (map[string]interface{}, error) {
	currentAuth := p.authMgr.GetCurrentAuth()

	return map[string]interface{}{
		"level":                currentAuth.Level,
		"level_name":           auth.AuthLevelString(currentAuth.Level),
		"user":                 currentAuth.User,
		"is_root":              currentAuth.IsRoot,
		"is_admin":             currentAuth.IsAdmin,
		"granted_features":     currentAuth.GrantedFeatures,
		"granted_at":           currentAuth.GrantedAt,
		"expires_at":           currentAuth.ExpiresAt,
		"can_elevate":          p.authMgr.CanElevate(),
		"feature_requirements": auth.GetFeaturePrivileges(),
	}, nil
}

func (p *OSXSecurityPlugin) executeAuthElevate(ctx context.Context, params map[string]interface{}) (map[string]interface{}, error) {
	targetLevel := auth.LevelEnhanced
	if level, ok := params["level"].(float64); ok {
		targetLevel = auth.AuthLevel(int(level))
	}

	reason := "Security analysis"
	if r, ok := params["reason"].(string); ok {
		reason = r
	}

	err := p.authMgr.RequestElevation(targetLevel, reason)
	if err != nil {
		return map[string]interface{}{
			"success": false,
			"error":   err.Error(),
		}, nil
	}

	return map[string]interface{}{
		"success":   true,
		"new_level": p.authMgr.GetCurrentAuth().Level,
	}, nil
}

func (p *OSXSecurityPlugin) executeAuthRevoke(ctx context.Context, params map[string]interface{}) (map[string]interface{}, error) {
	p.authMgr.RevokeElevation()

	return map[string]interface{}{
		"success":   true,
		"new_level": p.authMgr.GetCurrentAuth().Level,
	}, nil
}

func (p *OSXSecurityPlugin) executeFullAudit(ctx context.Context, params map[string]interface{}) (map[string]interface{}, error) {
	result := make(map[string]interface{})

	// DS Audit
	dsResult, err := p.dsAuditor.Audit()
	if err == nil {
		result["directory_services"] = map[string]interface{}{
			"total_users":  dsResult.TotalUsers,
			"admin_users":  dsResult.AdminUsers,
			"hidden_users": dsResult.HiddenUsers,
			"findings":     dsResult.Findings,
		}
	} else {
		result["directory_services_error"] = err.Error()
	}

	// Keychain Analysis (if authorized)
	if p.authMgr.IsAuthorized(auth.FeatureKeychainAnalyze) {
		keyResult, err := p.keyAnalyzer.Analyze()
		if err == nil {
			result["keychain"] = map[string]interface{}{
				"total_items": keyResult.TotalItems,
				"duplicates":  len(keyResult.Duplicates),
				"findings":    keyResult.Findings,
			}
		} else {
			result["keychain_error"] = err.Error()
		}
	} else {
		result["keychain"] = map[string]interface{}{
			"requires_auth": true,
		}
	}

	// Take snapshot
	snap, err := p.snapshotMgr.TakeSnapshot()
	if err == nil {
		result["snapshot"] = map[string]interface{}{
			"id":           snap.ID,
			"hash":         snap.Hash,
			"launch_items": len(snap.LaunchItems),
		}
	}

	// Collect all findings
	var allFindings []interface{}
	if dsResult != nil {
		for _, f := range dsResult.Findings {
			allFindings = append(allFindings, f)
		}
	}
	result["total_findings"] = len(allFindings)

	// Count by severity
	severityCounts := map[string]int{
		"critical": 0,
		"high":     0,
		"medium":   0,
		"low":      0,
	}
	if dsResult != nil {
		for _, f := range dsResult.Findings {
			severityCounts[f.Severity]++
		}
	}
	result["findings_by_severity"] = severityCounts

	return result, nil
}

func (p *OSXSecurityPlugin) executeStatus(ctx context.Context, params map[string]interface{}) (map[string]interface{}, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	result := map[string]interface{}{
		"plugin_name":    PluginName,
		"plugin_version": PluginVersion,
		"running":        p.running,
		"auth_level":     p.authMgr.GetCurrentAuth().Level,
	}

	if p.fsMonitor != nil {
		result["monitor_running"] = p.fsMonitor.IsRunning()
		result["monitored_paths"] = len(p.fsMonitor.GetMonitoredPaths())
	}

	result["event_buffer_count"] = len(p.eventBuffer)

	if p.lastDSAudit != nil {
		result["last_ds_audit"] = p.lastDSAudit.Timestamp
	}

	return result, nil
}

// Background processing

func (p *OSXSecurityPlugin) backgroundLoop() {
	snapshotTicker := time.NewTicker(p.snapshotInterval)
	authCheckTicker := time.NewTicker(1 * time.Minute)
	defer snapshotTicker.Stop()
	defer authCheckTicker.Stop()

	for {
		select {
		case <-p.stopCh:
			return

		case event := <-p.eventCh:
			p.mu.Lock()
			p.eventBuffer = append(p.eventBuffer, event)
			// Trim buffer if needed
			if len(p.eventBuffer) > p.eventBufferSize {
				p.eventBuffer = p.eventBuffer[len(p.eventBuffer)-p.eventBufferSize:]
			}
			p.mu.Unlock()

		case <-snapshotTicker.C:
			if p.autoSnapshot {
				if snap, err := p.snapshotMgr.TakeSnapshot(); err == nil {
					p.snapshotMgr.SaveSnapshot(snap)
				}
			}

		case <-authCheckTicker.C:
			p.authMgr.CheckExpiration()
		}
	}
}

func (p *OSXSecurityPlugin) handleFSEvent(event fsmonitor.Event) {
	// Non-blocking send to event channel
	select {
	case p.eventCh <- event:
	default:
		// Channel full, drop event
	}
}

// Standalone CLI mode

func runStandalone() {
	flag.Parse()
	args := flag.Args()

	if len(args) == 0 {
		printUsage()
		os.Exit(1)
	}

	plugin := &OSXSecurityPlugin{}
	if err := plugin.Configure(map[string]interface{}{}); err != nil {
		fmt.Fprintf(os.Stderr, "Error configuring plugin: %v\n", err)
		os.Exit(1)
	}

	ctx := context.Background()
	action := args[0]
	params := make(map[string]interface{})

	// Parse additional arguments
	for i := 1; i < len(args); i++ {
		if strings.Contains(args[i], "=") {
			parts := strings.SplitN(args[i], "=", 2)
			params[parts[0]] = parts[1]
		}
	}

	result, err := plugin.Execute(ctx, action, params)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	// Pretty print JSON result
	output, _ := json.MarshalIndent(result, "", "  ")
	fmt.Println(string(output))
}

func printUsage() {
	fmt.Println("AfterDark macOS Security Plugin v" + PluginVersion)
	fmt.Println()
	fmt.Println("Usage: osx-security <action> [params...]")
	fmt.Println()
	fmt.Println("Actions:")
	fmt.Println("  ds_audit          - Audit Directory Services (users/groups)")
	fmt.Println("  ds_get_user       - Get user details (username=<name>)")
	fmt.Println("  ds_get_admins     - List all admin users")
	fmt.Println("  ds_get_hidden     - List hidden users")
	fmt.Println()
	fmt.Println("  keychain_analyze  - Analyze keychain security")
	fmt.Println("  keychain_search   - Search keychain items (query=<term>)")
	fmt.Println("  keychain_duplicates - Find duplicate entries")
	fmt.Println()
	fmt.Println("  snapshot_take     - Take security snapshot")
	fmt.Println("  snapshot_list     - List available snapshots")
	fmt.Println("  snapshot_compare  - Compare snapshots (older=<id> newer=<id>)")
	fmt.Println("  snapshot_diff_latest - Diff with latest snapshot")
	fmt.Println()
	fmt.Println("  monitor_status    - Get monitor status")
	fmt.Println("  monitor_events    - Get recent events")
	fmt.Println()
	fmt.Println("  auth_status       - Show authorization status")
	fmt.Println("  auth_elevate      - Request elevated access")
	fmt.Println("  auth_revoke       - Revoke elevated access")
	fmt.Println()
	fmt.Println("  full_audit        - Run comprehensive audit")
	fmt.Println("  status            - Show plugin status")
	fmt.Println()
	fmt.Println("Examples:")
	fmt.Println("  osx-security ds_audit")
	fmt.Println("  osx-security ds_get_user username=john")
	fmt.Println("  osx-security keychain_search query=github")
	fmt.Println("  osx-security snapshot_compare older=abc123 newer=def456")
}

func main() {
	// Always run standalone for now
	// Plugin mode will be enabled when building with darkd SDK
	runStandalone()
}
