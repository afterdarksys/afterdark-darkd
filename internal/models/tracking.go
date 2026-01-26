package models

import "time"

// Process represents a running process on the system
type Process struct {
	PID         int32     `json:"pid"`
	PPID        int32     `json:"ppid"`
	Name        string    `json:"name"`
	Executable  string    `json:"executable"`
	CommandLine string    `json:"command_line,omitempty"`
	Username    string    `json:"username"`
	Status      string    `json:"status"`
	StartTime   time.Time `json:"start_time"`
	CPUPercent  float64   `json:"cpu_percent"`
	MemoryMB    float64   `json:"memory_mb"`
	Connections int       `json:"connections"` // Number of network connections
}

// ProcessSnapshot represents a point-in-time snapshot of all processes
type ProcessSnapshot struct {
	Timestamp time.Time   `json:"timestamp"`
	Hostname  string      `json:"hostname"`
	Processes []Process   `json:"processes"`
	Summary   ProcSummary `json:"summary"`
}

// ProcSummary provides high-level process statistics
type ProcSummary struct {
	Total    int     `json:"total"`
	Running  int     `json:"running"`
	Sleeping int     `json:"sleeping"`
	Zombie   int     `json:"zombie"`
	CPUTotal float64 `json:"cpu_total"`
	MemTotal float64 `json:"mem_total_mb"`
}

// SystemService represents a system daemon/service
type SystemService struct {
	Name        string    `json:"name"`
	DisplayName string    `json:"display_name,omitempty"`
	Description string    `json:"description,omitempty"`
	Status      string    `json:"status"`     // running, stopped, starting, stopping
	StartType   string    `json:"start_type"` // auto, manual, disabled
	Enabled     bool      `json:"enabled"`
	PID         int32     `json:"pid,omitempty"`
	Executable  string    `json:"executable,omitempty"`
	User        string    `json:"user,omitempty"`
	StartedAt   time.Time `json:"started_at,omitempty"`
}

// NetworkConnection represents an active network connection
type NetworkConnection struct {
	Protocol    string    `json:"protocol"`   // tcp, tcp6, udp, udp6
	LocalAddr   string    `json:"local_addr"` // IP address
	LocalPort   uint16    `json:"local_port"`
	RemoteAddr  string    `json:"remote_addr"` // IP address
	RemotePort  uint16    `json:"remote_port"`
	State       string    `json:"state"` // ESTABLISHED, LISTEN, TIME_WAIT, etc.
	PID         int32     `json:"pid"`
	ProcessName string    `json:"process_name"`
	Username    string    `json:"username,omitempty"`
	FirstSeen   time.Time `json:"first_seen"`
	LastSeen    time.Time `json:"last_seen"`
	Duration    float64   `json:"duration_secs"` // seconds
	BytesSent   uint64    `json:"bytes_sent,omitempty"`
	BytesRecv   uint64    `json:"bytes_recv,omitempty"`
}

// ConnectionKey uniquely identifies a connection for tracking
type ConnectionKey struct {
	Protocol   string
	LocalAddr  string
	LocalPort  uint16
	RemoteAddr string
	RemotePort uint16
}

// TrackedConnection tracks connection statistics over time
type TrackedConnection struct {
	Key           ConnectionKey `json:"key"`
	FirstSeen     time.Time     `json:"first_seen"`
	LastSeen      time.Time     `json:"last_seen"`
	Occurrences   int           `json:"occurrences"` // How many times seen
	TotalDuration float64       `json:"total_duration_secs"`
	ProcessName   string        `json:"process_name"`
	PID           int32         `json:"pid"`

	// Remote host info (resolved)
	RemoteHostname string `json:"remote_hostname,omitempty"`
	RemoteCountry  string `json:"remote_country,omitempty"`
	RemoteASN      string `json:"remote_asn,omitempty"`

	// Threat intel correlation
	ThreatScore    int    `json:"threat_score,omitempty"` // 0-100
	ThreatCategory string `json:"threat_category,omitempty"`
	Flagged        bool   `json:"flagged"`
}

// ConnectionSummary provides aggregated connection statistics
type ConnectionSummary struct {
	Timestamp       time.Time `json:"timestamp"`
	TotalActive     int       `json:"total_active"`
	Established     int       `json:"established"`
	Listening       int       `json:"listening"`
	TimeWait        int       `json:"time_wait"`
	UniqueRemoteIPs int       `json:"unique_remote_ips"`
	UniqueProcesses int       `json:"unique_processes"`

	// Top talkers
	TopDestinations []DestinationStat `json:"top_destinations"`
	TopProcesses    []ProcessConnStat `json:"top_processes"`
}

// DestinationStat tracks connection stats per destination
type DestinationStat struct {
	RemoteAddr     string  `json:"remote_addr"`
	RemoteHostname string  `json:"remote_hostname,omitempty"`
	RemotePort     uint16  `json:"remote_port"`
	Protocol       string  `json:"protocol"`
	Connections    int     `json:"connections"`
	TotalDuration  float64 `json:"total_duration_secs"`
	Occurrences    int     `json:"occurrences"`
	ThreatScore    int     `json:"threat_score,omitempty"`
}

// ProcessConnStat tracks connections per process
type ProcessConnStat struct {
	ProcessName     string `json:"process_name"`
	PID             int32  `json:"pid"`
	ActiveConns     int    `json:"active_connections"`
	UniqueRemoteIPs int    `json:"unique_remote_ips"`
}

// ConnectionEvent represents a connection change event
type ConnectionEvent struct {
	Timestamp  time.Time         `json:"timestamp"`
	EventType  string            `json:"event_type"` // new, closed, flagged
	Connection NetworkConnection `json:"connection"`
	Details    string            `json:"details,omitempty"`
}

// TrackingConfig holds configuration for process/connection tracking
type TrackingConfig struct {
	Enabled          bool          `yaml:"enabled" json:"enabled"`
	ProcessInterval  time.Duration `yaml:"process_interval" json:"process_interval"`
	NetworkInterval  time.Duration `yaml:"network_interval" json:"network_interval"`
	ServiceInterval  time.Duration `yaml:"service_interval" json:"service_interval"`
	RetentionPeriod  time.Duration `yaml:"retention_period" json:"retention_period"`
	ResolveHostnames bool          `yaml:"resolve_hostnames" json:"resolve_hostnames"`
	TrackLocalConns  bool          `yaml:"track_local_conns" json:"track_local_conns"`
}
