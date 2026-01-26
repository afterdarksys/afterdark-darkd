package models

import "time"

// DNSTunnelAnalysis contains DNS tunneling detection results for a domain
type DNSTunnelAnalysis struct {
	Domain           string `json:"domain"`
	BaseDomain       string `json:"base_domain"` // e.g., "evil.com" from "data.evil.com"
	QueryCount       int    `json:"query_count"`
	UniqueSubdomains int    `json:"unique_subdomains"`

	// Entropy Metrics
	AvgSubdomainLen float64 `json:"avg_subdomain_length"`
	MaxSubdomainLen int     `json:"max_subdomain_length"`
	AvgEntropy      float64 `json:"avg_entropy"` // Shannon entropy
	MaxEntropy      float64 `json:"max_entropy"`
	MinEntropy      float64 `json:"min_entropy"`

	// Query Pattern Analysis
	QueriesPerMinute float64 `json:"queries_per_minute"`
	TXTQueryRatio    float64 `json:"txt_query_ratio"`
	NXDOMAINRatio    float64 `json:"nxdomain_ratio"`
	NULLQueryCount   int     `json:"null_query_count"`

	// Encoding Detection
	EncodingDetected string  `json:"encoding_detected"` // "base64", "base32", "hex", "none"
	EncodingScore    float64 `json:"encoding_score"`

	// Scoring
	TunnelingScore float64 `json:"tunneling_score"` // 0-100
	IsTunnelLikely bool    `json:"is_tunnel_likely"`
	TunnelType     string  `json:"tunnel_type"` // "iodine", "dnscat2", "dns2tcp", "cobalt_strike", "unknown"
	Confidence     float64 `json:"confidence"`  // 0.0-1.0

	// Context
	FirstSeen    time.Time `json:"first_seen"`
	LastQuery    time.Time `json:"last_query"`
	LastAnalyzed time.Time `json:"last_analyzed"`

	// Process info (if available)
	ProcessName string `json:"process_name,omitempty"`
	ProcessPID  int    `json:"process_pid,omitempty"`

	// Threat Intel
	ThreatIntelMatch bool   `json:"threat_intel_match"`
	ThreatCategory   string `json:"threat_category,omitempty"`
}

// TunnelDNSQuery represents a captured DNS query for tunnel analysis
type TunnelDNSQuery struct {
	Timestamp    time.Time     `json:"timestamp"`
	Domain       string        `json:"domain"`
	Subdomain    string        `json:"subdomain"`     // The part before base domain
	RecordType   string        `json:"record_type"`   // A, AAAA, TXT, MX, CNAME, NULL, etc.
	ResponseCode string        `json:"response_code"` // NOERROR, NXDOMAIN, SERVFAIL
	ResponseSize int           `json:"response_size"`
	QuerySize    int           `json:"query_size"`
	Latency      time.Duration `json:"latency_ms"`
	ProcessPID   int           `json:"process_pid,omitempty"`
	ProcessName  string        `json:"process_name,omitempty"`
	ServerIP     string        `json:"server_ip,omitempty"`
}

// DNSDomainStats tracks statistics for a domain
type DNSDomainStats struct {
	Domain        string
	Queries       []TunnelDNSQuery
	Subdomains    map[string]int // subdomain -> count
	RecordTypes   map[string]int // record type -> count
	ResponseCodes map[string]int // response code -> count
	FirstSeen     time.Time
	LastSeen      time.Time
	TotalBytes    int64
}

// AddQuery adds a query to the domain stats
func (s *DNSDomainStats) AddQuery(q TunnelDNSQuery) {
	s.Queries = append(s.Queries, q)

	if s.Subdomains == nil {
		s.Subdomains = make(map[string]int)
	}
	s.Subdomains[q.Subdomain]++

	if s.RecordTypes == nil {
		s.RecordTypes = make(map[string]int)
	}
	s.RecordTypes[q.RecordType]++

	if s.ResponseCodes == nil {
		s.ResponseCodes = make(map[string]int)
	}
	s.ResponseCodes[q.ResponseCode]++

	if s.FirstSeen.IsZero() {
		s.FirstSeen = q.Timestamp
	}
	s.LastSeen = q.Timestamp
	s.TotalBytes += int64(q.QuerySize + q.ResponseSize)

	// Keep only last 1000 queries per domain
	if len(s.Queries) > 1000 {
		s.Queries = s.Queries[100:]
	}
}

// DNSTunnelingTool defines characteristics of known DNS tunneling tools
type DNSTunnelingTool struct {
	Name            string
	Description     string
	RecordTypes     []string   // Preferred record types
	SubdomainLen    [2]int     // Min/max typical subdomain length
	EntropyRange    [2]float64 // Min/max entropy
	Encoding        string     // Typical encoding used
	Characteristics []string   // Other identifying features
}

// KnownDNSTunnelingTools contains signatures for known DNS tunneling tools
var KnownDNSTunnelingTools = []DNSTunnelingTool{
	{
		Name:         "iodine",
		Description:  "IP-over-DNS tunneling",
		RecordTypes:  []string{"NULL", "TXT", "MX", "CNAME", "A"},
		SubdomainLen: [2]int{50, 200},
		EntropyRange: [2]float64{4.0, 5.5},
		Encoding:     "base128",
		Characteristics: []string{
			"Very long subdomains",
			"Uses NULL records by default",
			"High query frequency",
		},
	},
	{
		Name:         "dnscat2",
		Description:  "C2 over DNS",
		RecordTypes:  []string{"TXT", "MX", "CNAME", "A", "AAAA"},
		SubdomainLen: [2]int{20, 63},
		EntropyRange: [2]float64{3.5, 5.0},
		Encoding:     "hex",
		Characteristics: []string{
			"Hex-encoded subdomains",
			"Structured message format",
			"Session-based communication",
		},
	},
	{
		Name:         "dns2tcp",
		Description:  "TCP-over-DNS tunneling",
		RecordTypes:  []string{"TXT", "KEY"},
		SubdomainLen: [2]int{30, 100},
		EntropyRange: [2]float64{4.0, 5.0},
		Encoding:     "base64",
		Characteristics: []string{
			"Base64 encoded data",
			"TXT record preference",
			"Bidirectional tunnel",
		},
	},
	{
		Name:         "cobalt_strike_dns",
		Description:  "Cobalt Strike DNS beacon",
		RecordTypes:  []string{"A", "TXT", "AAAA"},
		SubdomainLen: [2]int{10, 50},
		EntropyRange: [2]float64{3.0, 4.5},
		Encoding:     "custom",
		Characteristics: []string{
			"Hybrid beacon approach",
			"A records for check-in",
			"TXT for data transfer",
		},
	},
	{
		Name:         "godoh",
		Description:  "DNS-over-HTTPS tunneling tool",
		RecordTypes:  []string{"A", "TXT"},
		SubdomainLen: [2]int{20, 60},
		EntropyRange: [2]float64{3.5, 5.0},
		Encoding:     "base32",
		Characteristics: []string{
			"Uses DoH providers",
			"Base32 encoded commands",
		},
	},
}

// DNSTunnelEvent represents a tunnel detection event for alerting
type DNSTunnelEvent struct {
	Timestamp      time.Time          `json:"timestamp"`
	AgentID        string             `json:"agent_id"`
	Hostname       string             `json:"hostname"`
	Analysis       *DNSTunnelAnalysis `json:"analysis"`
	Action         string             `json:"action"`          // "detected", "blocked"
	Severity       string             `json:"severity"`        // "low", "medium", "high", "critical"
	MITRETechnique string             `json:"mitre_technique"` // T1071.004
	SampleQueries  []TunnelDNSQuery   `json:"sample_queries,omitempty"`
}

// Common DNS record type constants
const (
	DNSRecordA     = "A"
	DNSRecordAAAA  = "AAAA"
	DNSRecordTXT   = "TXT"
	DNSRecordMX    = "MX"
	DNSRecordCNAME = "CNAME"
	DNSRecordNS    = "NS"
	DNSRecordSOA   = "SOA"
	DNSRecordPTR   = "PTR"
	DNSRecordNULL  = "NULL"
	DNSRecordKEY   = "KEY"
)

// DNS response codes
const (
	DNSResponseNOERROR  = "NOERROR"
	DNSResponseNXDOMAIN = "NXDOMAIN"
	DNSResponseSERVFAIL = "SERVFAIL"
	DNSResponseREFUSED  = "REFUSED"
)
