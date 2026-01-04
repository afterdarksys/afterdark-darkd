// Package plugin provides the plugin architecture for afterdark-darkd.
// It uses hashicorp/go-plugin for cross-platform, multi-language plugin support.
package plugin

import (
	"context"
	"time"
)

// PluginType identifies the kind of plugin
type PluginType string

const (
	PluginTypeService    PluginType = "service"
	PluginTypeDataSource PluginType = "datasource"
	PluginTypeStorage    PluginType = "storage"
	PluginTypeReporter   PluginType = "reporter"
	PluginTypeCLI        PluginType = "cli"
	PluginTypeFirewall   PluginType = "firewall"
)

// PluginInfo contains metadata about a plugin
type PluginInfo struct {
	Name        string       `json:"name"`
	Version     string       `json:"version"`
	Type        PluginType   `json:"type"`
	Description string       `json:"description"`
	Author      string       `json:"author"`
	License     string       `json:"license"`
	Capabilities []string    `json:"capabilities,omitempty"`
}

// PluginState represents the current state of a plugin
type PluginState int

const (
	PluginStateUnknown PluginState = iota
	PluginStateLoading
	PluginStateReady
	PluginStateRunning
	PluginStateStopping
	PluginStateStopped
	PluginStateError
)

func (s PluginState) String() string {
	switch s {
	case PluginStateLoading:
		return "loading"
	case PluginStateReady:
		return "ready"
	case PluginStateRunning:
		return "running"
	case PluginStateStopping:
		return "stopping"
	case PluginStateStopped:
		return "stopped"
	case PluginStateError:
		return "error"
	default:
		return "unknown"
	}
}

// PluginHealth represents health status of a plugin
type PluginHealth struct {
	State     PluginState            `json:"state"`
	Message   string                 `json:"message,omitempty"`
	LastCheck time.Time              `json:"last_check"`
	Metrics   map[string]interface{} `json:"metrics,omitempty"`
}

// ServicePlugin is the interface for service-type plugins
// These add new monitoring/security services to the daemon
type ServicePlugin interface {
	// Info returns plugin metadata
	Info() PluginInfo

	// Configure sets up the plugin with the provided configuration
	Configure(config map[string]interface{}) error

	// Start initializes and starts the service
	Start(ctx context.Context) error

	// Stop gracefully shuts down the service
	Stop(ctx context.Context) error

	// Health returns the current health status
	Health() PluginHealth

	// Execute runs a specific action and returns results
	Execute(ctx context.Context, action string, params map[string]interface{}) (map[string]interface{}, error)
}

// DataSourcePlugin is the interface for data source plugins
// These provide threat intel feeds, API integrations, etc.
type DataSourcePlugin interface {
	// Info returns plugin metadata
	Info() PluginInfo

	// Configure sets up the data source
	Configure(config map[string]interface{}) error

	// Connect establishes connection to the data source
	Connect(ctx context.Context) error

	// Disconnect closes the connection
	Disconnect(ctx context.Context) error

	// Query retrieves data from the source
	Query(ctx context.Context, query string, params map[string]interface{}) ([]map[string]interface{}, error)

	// Subscribe sets up real-time updates (optional)
	Subscribe(ctx context.Context, topic string, handler func(data map[string]interface{})) error

	// Health returns the current health status
	Health() PluginHealth
}

// StoragePlugin is the interface for storage backend plugins
// These provide alternative storage mechanisms (databases, cloud, etc.)
type StoragePlugin interface {
	// Info returns plugin metadata
	Info() PluginInfo

	// Configure sets up the storage backend
	Configure(config map[string]interface{}) error

	// Connect establishes connection to storage
	Connect(ctx context.Context) error

	// Disconnect closes the connection
	Disconnect(ctx context.Context) error

	// Get retrieves a value by key from a collection
	Get(ctx context.Context, collection, key string) ([]byte, error)

	// Set stores a value by key in a collection
	Set(ctx context.Context, collection, key string, value []byte) error

	// Delete removes a key from a collection
	Delete(ctx context.Context, collection, key string) error

	// List returns all keys in a collection matching a prefix
	List(ctx context.Context, collection, prefix string) ([]string, error)

	// Query performs a query on the storage (implementation-specific)
	Query(ctx context.Context, collection string, query map[string]interface{}) ([][]byte, error)

	// Health returns the current health status
	Health() PluginHealth
}

// ReporterPlugin is the interface for report generator plugins
// These generate reports in various formats (PDF, HTML, etc.)
type ReporterPlugin interface {
	// Info returns plugin metadata
	Info() PluginInfo

	// Configure sets up the reporter
	Configure(config map[string]interface{}) error

	// SupportedFormats returns list of output formats (e.g., "pdf", "html", "csv")
	SupportedFormats() []string

	// Generate creates a report from the provided data
	Generate(ctx context.Context, format string, data map[string]interface{}) ([]byte, error)

	// Health returns the current health status
	Health() PluginHealth
}

// CLICommand represents a CLI command provided by a plugin
type CLICommand struct {
	Name        string       `json:"name"`
	Description string       `json:"description"`
	Usage       string       `json:"usage"`
	Flags       []CLIFlag    `json:"flags,omitempty"`
	Subcommands []CLICommand `json:"subcommands,omitempty"`
}

// CLIFlag represents a command-line flag
type CLIFlag struct {
	Name        string `json:"name"`
	Shorthand   string `json:"shorthand,omitempty"`
	Description string `json:"description"`
	Type        string `json:"type"` // "string", "int", "bool", "stringSlice"
	Default     string `json:"default,omitempty"`
	Required    bool   `json:"required"`
}

// CLIPlugin is the interface for CLI command plugins
// These add new commands to the admin and user CLIs
type CLIPlugin interface {
	// Info returns plugin metadata
	Info() PluginInfo

	// Configure sets up the CLI plugin
	Configure(config map[string]interface{}) error

	// Commands returns the list of commands provided by this plugin
	Commands() []CLICommand

	// Execute runs a command with the given arguments and flags
	Execute(ctx context.Context, command string, args []string, flags map[string]interface{}) (string, error)

	// Health returns the current health status
	Health() PluginHealth
}

// FirewallRule represents a firewall rule
type FirewallRule struct {
	ID            string    `json:"id"`
	Name          string    `json:"name"`
	Description   string    `json:"description"`
	Direction     string    `json:"direction"`      // "inbound", "outbound", "both"
	Action        string    `json:"action"`         // "allow", "deny", "drop", "reject"
	Protocol      string    `json:"protocol"`       // "tcp", "udp", "icmp", "any"
	SourceIP      string    `json:"source_ip"`      // CIDR notation
	SourcePort    string    `json:"source_port"`    // Port or range
	DestIP        string    `json:"dest_ip"`
	DestPort      string    `json:"dest_port"`
	Interface     string    `json:"interface"`
	Priority      int       `json:"priority"`
	Enabled       bool      `json:"enabled"`
	CreatedAt     time.Time `json:"created_at"`
	ExpiresAt     time.Time `json:"expires_at,omitempty"`
	Reason        string    `json:"reason"`
	SourceService string    `json:"source_service"`
	HitCount      int64     `json:"hit_count"`
	LastHitAt     time.Time `json:"last_hit_at,omitempty"`
}

// BlockedIP represents a blocked IP address
type BlockedIP struct {
	IP            string    `json:"ip"`
	Reason        string    `json:"reason"`
	SourceService string    `json:"source_service"`
	BlockedAt     time.Time `json:"blocked_at"`
	ExpiresAt     time.Time `json:"expires_at,omitempty"`
	ThreatScore   int       `json:"threat_score"`
	Categories    []string  `json:"categories"`
}

// FirewallStatus represents the current firewall state
type FirewallStatus struct {
	Enabled             bool              `json:"enabled"`
	Backend             string            `json:"backend"`
	Version             string            `json:"version"`
	TotalRules          int               `json:"total_rules"`
	ActiveRules         int               `json:"active_rules"`
	BlockedIPs          int               `json:"blocked_ips"`
	DefaultDenyInbound  bool              `json:"default_deny_inbound"`
	DefaultDenyOutbound bool              `json:"default_deny_outbound"`
	LastUpdated         time.Time         `json:"last_updated"`
	Capabilities        map[string]string `json:"capabilities"`
}

// FirewallPlugin is the interface for firewall plugins
// These provide OS-specific firewall control (iptables, pf, Windows Firewall)
type FirewallPlugin interface {
	// Info returns plugin metadata
	Info() PluginInfo

	// Configure sets up the firewall plugin
	Configure(config map[string]interface{}) error

	// Health returns the current health status
	Health() PluginHealth

	// Firewall control
	Enable(ctx context.Context, enable bool, defaultDenyInbound bool, defaultDenyOutbound bool) (*FirewallStatus, error)
	Status(ctx context.Context) (*FirewallStatus, error)

	// IP blocking
	BlockIP(ctx context.Context, ip string, reason string, sourceService string, durationSeconds int64, threatScore int, categories []string) (*BlockedIP, error)
	UnblockIP(ctx context.Context, ip string) error
	ListBlockedIPs(ctx context.Context, limit int, offset int, sourceService string) ([]BlockedIP, int, error)
	IsIPBlocked(ctx context.Context, ip string) (bool, *BlockedIP, error)

	// Rule management
	AddRule(ctx context.Context, rule *FirewallRule) (*FirewallRule, error)
	RemoveRule(ctx context.Context, ruleID string) error
	UpdateRule(ctx context.Context, rule *FirewallRule) (*FirewallRule, error)
	ListRules(ctx context.Context, limit int, offset int, direction string, enabledOnly bool) ([]FirewallRule, int, error)
	GetRule(ctx context.Context, ruleID string) (*FirewallRule, error)

	// Bulk operations
	SyncBlocklist(ctx context.Context, blockedIPs []BlockedIP, replace bool) (added int, removed int, unchanged int, err error)
	FlushRules(ctx context.Context, flushBlocks bool, flushRules bool, keepEssential bool) (rulesFlushed int, blocksFlushed int, err error)

	// Port management (convenience)
	OpenPort(ctx context.Context, port int, protocol string, direction string, sourceIP string, description string) (*FirewallRule, error)
	ClosePort(ctx context.Context, port int, protocol string, direction string) error
}
