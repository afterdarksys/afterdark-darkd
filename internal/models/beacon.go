package models

import "time"

// BeaconAnalysis contains C2 beaconing detection results for a connection
type BeaconAnalysis struct {
	ConnectionKey string `json:"connection_key"`
	RemoteAddr    string `json:"remote_addr"`
	RemotePort    int    `json:"remote_port"`
	ProcessName   string `json:"process_name"`
	ProcessPID    int    `json:"process_pid"`

	// Timing Analysis
	MeanInterval   time.Duration `json:"mean_interval_ms"`
	StdDeviation   float64       `json:"std_deviation_ms"`
	CoeffVariation float64       `json:"coeff_variation"` // StdDev/Mean - key beacon indicator
	JitterPercent  float64       `json:"jitter_percent"`

	// Pattern Detection
	ConnectionCount int   `json:"connection_count"`
	AvgBytesOut     int64 `json:"avg_bytes_out"`
	AvgBytesIn      int64 `json:"avg_bytes_in"`

	// Scoring
	BeaconScore      float64 `json:"beacon_score"` // 0-100
	IsBeaconLikely   bool    `json:"is_beacon_likely"`
	DetectedPattern  string  `json:"detected_pattern"`   // "fixed", "jitter", "exponential", "random"
	MatchedFramework string  `json:"matched_framework"`  // "cobalt_strike", "metasploit", etc.
	Confidence       float64 `json:"confidence"`         // 0.0-1.0

	// Context
	FirstSeen    time.Time `json:"first_seen"`
	LastSeen     time.Time `json:"last_seen"`
	LastAnalyzed time.Time `json:"last_analyzed"`

	// Threat Intel correlation
	ThreatIntelMatch bool   `json:"threat_intel_match"`
	ThreatCategory   string `json:"threat_category,omitempty"`
}

// C2Framework defines characteristics of known C2 frameworks
type C2Framework struct {
	Name           string
	Description    string
	MinInterval    time.Duration
	MaxInterval    time.Duration
	DefaultJitter  float64   // Typical jitter percentage
	JitterRange    [2]float64 // Min/max jitter %
	TypicalPorts   []int
	UserAgents     []string // For HTTP-based C2
	DNSPatterns    []string // DNS beacon patterns
	HTTPPaths      []string // Common HTTP paths
}

// KnownC2Frameworks contains signatures for common C2 tools
var KnownC2Frameworks = []C2Framework{
	{
		Name:          "cobalt_strike",
		Description:   "Cobalt Strike Beacon",
		MinInterval:   30 * time.Second,
		MaxInterval:   5 * time.Minute,
		DefaultJitter: 0.25, // 25% default jitter
		JitterRange:   [2]float64{0.0, 0.50},
		TypicalPorts:  []int{443, 80, 8080, 8443, 50050},
		UserAgents: []string{
			"Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0)",
			"Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.2; WOW64; Trident/6.0)",
		},
		HTTPPaths: []string{"/pixel.gif", "/submit.php", "/__utm.gif", "/IE9CompatViewList.xml"},
	},
	{
		Name:          "metasploit",
		Description:   "Metasploit Meterpreter",
		MinInterval:   1 * time.Second,
		MaxInterval:   30 * time.Second,
		DefaultJitter: 0.10,
		JitterRange:   [2]float64{0.0, 0.20},
		TypicalPorts:  []int{4444, 443, 8080, 1337},
		HTTPPaths:     []string{"/"},
	},
	{
		Name:          "empire",
		Description:   "PowerShell Empire",
		MinInterval:   5 * time.Second,
		MaxInterval:   60 * time.Second,
		DefaultJitter: 0.20,
		JitterRange:   [2]float64{0.0, 0.20},
		TypicalPorts:  []int{443, 80, 8080},
		HTTPPaths:     []string{"/admin/get.php", "/news.php", "/login/process.php"},
	},
	{
		Name:          "covenant",
		Description:   "Covenant C2",
		MinInterval:   5 * time.Second,
		MaxInterval:   60 * time.Second,
		DefaultJitter: 0.10,
		JitterRange:   [2]float64{0.0, 0.10},
		TypicalPorts:  []int{443, 80, 8080},
	},
	{
		Name:          "sliver",
		Description:   "Sliver C2",
		MinInterval:   30 * time.Second,
		MaxInterval:   5 * time.Minute,
		DefaultJitter: 0.30,
		JitterRange:   [2]float64{0.0, 0.30},
		TypicalPorts:  []int{443, 8888, 31337},
	},
	{
		Name:          "poshc2",
		Description:   "PoshC2",
		MinInterval:   5 * time.Second,
		MaxInterval:   120 * time.Second,
		DefaultJitter: 0.20,
		JitterRange:   [2]float64{0.0, 0.50},
		TypicalPorts:  []int{443, 80},
	},
	{
		Name:          "brute_ratel",
		Description:   "Brute Ratel C4",
		MinInterval:   30 * time.Second,
		MaxInterval:   10 * time.Minute,
		DefaultJitter: 0.40,
		JitterRange:   [2]float64{0.10, 0.50},
		TypicalPorts:  []int{443, 8443},
	},
	{
		Name:          "havoc",
		Description:   "Havoc C2",
		MinInterval:   5 * time.Second,
		MaxInterval:   120 * time.Second,
		DefaultJitter: 0.25,
		JitterRange:   [2]float64{0.0, 0.40},
		TypicalPorts:  []int{443, 40056},
	},
}

// BeaconEvent represents a beacon detection event for alerting
type BeaconEvent struct {
	Timestamp      time.Time       `json:"timestamp"`
	AgentID        string          `json:"agent_id"`
	Hostname       string          `json:"hostname"`
	Analysis       *BeaconAnalysis `json:"analysis"`
	Action         string          `json:"action"` // "detected", "blocked", "quarantined"
	Severity       string          `json:"severity"` // "low", "medium", "high", "critical"
	MITRETechnique string          `json:"mitre_technique"` // T1071, T1573, etc.
}

// ConnectionTiming tracks timing data for beacon analysis
type ConnectionTiming struct {
	Timestamps    []time.Time     `json:"-"`
	Intervals     []time.Duration `json:"-"`
	BytesSent     []int64         `json:"-"`
	BytesReceived []int64         `json:"-"`
}

// AddTimestamp records a new connection timestamp
func (ct *ConnectionTiming) AddTimestamp(t time.Time, bytesSent, bytesReceived int64) {
	if len(ct.Timestamps) > 0 {
		lastTime := ct.Timestamps[len(ct.Timestamps)-1]
		interval := t.Sub(lastTime)
		ct.Intervals = append(ct.Intervals, interval)
	}
	ct.Timestamps = append(ct.Timestamps, t)
	ct.BytesSent = append(ct.BytesSent, bytesSent)
	ct.BytesReceived = append(ct.BytesReceived, bytesReceived)

	// Keep only last 100 timestamps to prevent memory growth
	if len(ct.Timestamps) > 100 {
		ct.Timestamps = ct.Timestamps[1:]
		ct.Intervals = ct.Intervals[1:]
		ct.BytesSent = ct.BytesSent[1:]
		ct.BytesReceived = ct.BytesReceived[1:]
	}
}

// GetIntervalCount returns the number of recorded intervals
func (ct *ConnectionTiming) GetIntervalCount() int {
	return len(ct.Intervals)
}
