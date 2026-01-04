package models

import (
	"time"
)

// DetonationSample represents a file submitted for analysis
type DetonationSample struct {
	ID           string            `json:"id"`
	FileName     string            `json:"file_name"`
	FileSize     int64             `json:"file_size"`
	FilePath     string            `json:"file_path"`
	MimeType     string            `json:"mime_type"`
	Hashes       FileHashes        `json:"hashes"`
	Status       DetonationStatus  `json:"status"`
	Verdict      MalwareVerdict    `json:"verdict"`
	Location     SampleLocation    `json:"location"`
	Frequency    SampleFrequency   `json:"frequency"`
	SubmittedAt  time.Time         `json:"submitted_at"`
	CompletedAt  *time.Time        `json:"completed_at,omitempty"`
	Report       *DetonationReport `json:"report,omitempty"`
	Tags         []string          `json:"tags,omitempty"`
	UploadedToPortal bool          `json:"uploaded_to_portal"`
}

// FileHashes contains various hash representations of a file
type FileHashes struct {
	MD5       string `json:"md5"`
	SHA1      string `json:"sha1"`
	SHA256    string `json:"sha256"`
	SHA512    string `json:"sha512,omitempty"`
	SSDeep    string `json:"ssdeep,omitempty"`    // Fuzzy hash for similarity
	TLSH      string `json:"tlsh,omitempty"`      // Trend Micro Locality Sensitive Hash
	ImpHash   string `json:"imphash,omitempty"`   // Import hash for PE files
}

// DetonationStatus represents the current state of analysis
type DetonationStatus string

const (
	DetonationStatusPending    DetonationStatus = "pending"
	DetonationStatusQueued     DetonationStatus = "queued"
	DetonationStatusAnalyzing  DetonationStatus = "analyzing"
	DetonationStatusDetonating DetonationStatus = "detonating"
	DetonationStatusCompleted  DetonationStatus = "completed"
	DetonationStatusFailed     DetonationStatus = "failed"
	DetonationStatusTimeout    DetonationStatus = "timeout"
)

// MalwareVerdict represents the analysis result
type MalwareVerdict string

const (
	VerdictUnknown    MalwareVerdict = "unknown"
	VerdictClean      MalwareVerdict = "clean"
	VerdictSuspicious MalwareVerdict = "suspicious"
	VerdictMalicious  MalwareVerdict = "malicious"
	VerdictPUA        MalwareVerdict = "pua"        // Potentially Unwanted Application
	VerdictGrayware   MalwareVerdict = "grayware"
)

// SampleLocation tracks where the sample was detected
type SampleLocation struct {
	EndpointID   string `json:"endpoint_id"`
	Hostname     string `json:"hostname"`
	IPAddress    string `json:"ip_address"`
	Region       string `json:"region"`           // Geographic region (us-east, eu-west, etc.)
	NetworkZone  string `json:"network_zone"`     // Internal network segment
	NetworkName  string `json:"network_name"`     // Network/VLAN name
	SiteID       string `json:"site_id"`          // Physical site identifier
	Department   string `json:"department,omitempty"`
	DetectedPath string `json:"detected_path"`    // Original file path where detected
	Username     string `json:"username,omitempty"`
}

// SampleFrequency tracks how often this sample has been seen
type SampleFrequency struct {
	TotalCount        int64     `json:"total_count"`         // Total times seen across all endpoints
	UniqueEndpoints   int       `json:"unique_endpoints"`    // Number of unique endpoints
	UniqueRegions     int       `json:"unique_regions"`      // Number of unique regions
	UniqueNetworks    int       `json:"unique_networks"`     // Number of unique networks
	FirstSeen         time.Time `json:"first_seen"`
	LastSeen          time.Time `json:"last_seen"`
	SeenInLast24h     int64     `json:"seen_in_last_24h"`
	SeenInLast7d      int64     `json:"seen_in_last_7d"`
	SeenInLast30d     int64     `json:"seen_in_last_30d"`
	TrendDirection    string    `json:"trend_direction"`     // increasing, decreasing, stable
	PrevalenceScore   float64   `json:"prevalence_score"`    // 0-100 score
}

// DetonationReport contains the full analysis results
type DetonationReport struct {
	ID                string              `json:"id"`
	SampleID          string              `json:"sample_id"`
	Duration          time.Duration       `json:"duration"`
	SandboxType       string              `json:"sandbox_type"`      // docker, vm, native
	OSEnvironment     string              `json:"os_environment"`    // windows-10, ubuntu-22, macos-14
	StaticAnalysis    *StaticAnalysis     `json:"static_analysis,omitempty"`
	DynamicAnalysis   *DynamicAnalysis    `json:"dynamic_analysis,omitempty"`
	NetworkActivity   *NetworkActivity    `json:"network_activity,omitempty"`
	FileActivity      *FileActivity       `json:"file_activity,omitempty"`
	RegistryActivity  *RegistryActivity   `json:"registry_activity,omitempty"`
	ProcessActivity   *ProcessActivity    `json:"process_activity,omitempty"`
	Signatures        []SignatureMatch    `json:"signatures,omitempty"`
	ThreatScore       int                 `json:"threat_score"`      // 0-100
	Confidence        float64             `json:"confidence"`        // 0.0-1.0
	MITRE             []MITREMapping      `json:"mitre,omitempty"`
	IOCs              []IOC               `json:"iocs,omitempty"`
	Screenshots       []string            `json:"screenshots,omitempty"` // Base64 or URLs
	GeneratedAt       time.Time           `json:"generated_at"`
}

// StaticAnalysis contains results from static file analysis
type StaticAnalysis struct {
	FileType          string            `json:"file_type"`
	Magic             string            `json:"magic"`
	Entropy           float64           `json:"entropy"`
	IsPacked          bool              `json:"is_packed"`
	PackerName        string            `json:"packer_name,omitempty"`
	IsEncrypted       bool              `json:"is_encrypted"`
	IsSigned          bool              `json:"is_signed"`
	SignatureValid    bool              `json:"signature_valid"`
	SignerInfo        *SignerInfo       `json:"signer_info,omitempty"`
	Strings           []SuspiciousString `json:"strings,omitempty"`
	Imports           []ImportInfo      `json:"imports,omitempty"`
	Exports           []string          `json:"exports,omitempty"`
	Sections          []SectionInfo     `json:"sections,omitempty"`
	YaraMatches       []string          `json:"yara_matches,omitempty"`
}

// SignerInfo contains code signing information
type SignerInfo struct {
	Subject      string    `json:"subject"`
	Issuer       string    `json:"issuer"`
	SerialNumber string    `json:"serial_number"`
	ValidFrom    time.Time `json:"valid_from"`
	ValidTo      time.Time `json:"valid_to"`
	Thumbprint   string    `json:"thumbprint"`
}

// SuspiciousString represents a potentially malicious string found in the file
type SuspiciousString struct {
	Value    string `json:"value"`
	Category string `json:"category"` // url, ip, registry, api_call, crypto
	Offset   int64  `json:"offset"`
}

// ImportInfo represents an imported function/library
type ImportInfo struct {
	Library   string   `json:"library"`
	Functions []string `json:"functions"`
}

// SectionInfo represents a PE/ELF section
type SectionInfo struct {
	Name         string  `json:"name"`
	VirtualSize  int64   `json:"virtual_size"`
	RawSize      int64   `json:"raw_size"`
	Entropy      float64 `json:"entropy"`
	Permissions  string  `json:"permissions"`
	IsSuspicious bool    `json:"is_suspicious"`
}

// DynamicAnalysis contains results from dynamic/behavioral analysis
type DynamicAnalysis struct {
	ExitCode         int      `json:"exit_code"`
	Runtime          float64  `json:"runtime_seconds"`
	CrashedOrHung    bool     `json:"crashed_or_hung"`
	DetectedEvasion  bool     `json:"detected_evasion"`
	EvasionTechniques []string `json:"evasion_techniques,omitempty"`
	BehaviorSummary  string   `json:"behavior_summary"`
}

// NetworkActivity captures network behavior during detonation
type NetworkActivity struct {
	DNSQueries       []DNSQuery       `json:"dns_queries,omitempty"`
	HTTPRequests     []HTTPRequest    `json:"http_requests,omitempty"`
	TCPConnections   []Connection     `json:"tcp_connections,omitempty"`
	UDPConnections   []Connection     `json:"udp_connections,omitempty"`
	TotalBytesSent   int64            `json:"total_bytes_sent"`
	TotalBytesRecv   int64            `json:"total_bytes_recv"`
	ContactedIPs     []string         `json:"contacted_ips,omitempty"`
	ContactedDomains []string         `json:"contacted_domains,omitempty"`
}

// DNSQuery represents a DNS lookup made during detonation
type DNSQuery struct {
	Query     string   `json:"query"`
	Type      string   `json:"type"`
	Responses []string `json:"responses,omitempty"`
	Timestamp time.Time `json:"timestamp"`
}

// HTTPRequest represents an HTTP request made during detonation
type HTTPRequest struct {
	Method    string            `json:"method"`
	URL       string            `json:"url"`
	Headers   map[string]string `json:"headers,omitempty"`
	Body      string            `json:"body,omitempty"`
	Response  int               `json:"response_code"`
	Timestamp time.Time         `json:"timestamp"`
}

// Connection represents a network connection
type Connection struct {
	DestIP    string    `json:"dest_ip"`
	DestPort  int       `json:"dest_port"`
	BytesSent int64     `json:"bytes_sent"`
	BytesRecv int64     `json:"bytes_recv"`
	Timestamp time.Time `json:"timestamp"`
}

// FileActivity captures file system operations
type FileActivity struct {
	FilesCreated   []FileOp `json:"files_created,omitempty"`
	FilesModified  []FileOp `json:"files_modified,omitempty"`
	FilesDeleted   []string `json:"files_deleted,omitempty"`
	FilesRead      []string `json:"files_read,omitempty"`
	DroppedFiles   []DroppedFile `json:"dropped_files,omitempty"`
}

// FileOp represents a file operation
type FileOp struct {
	Path      string    `json:"path"`
	Size      int64     `json:"size,omitempty"`
	Timestamp time.Time `json:"timestamp"`
}

// DroppedFile represents a file created/dropped by the sample
type DroppedFile struct {
	Path     string     `json:"path"`
	Size     int64      `json:"size"`
	Hashes   FileHashes `json:"hashes"`
	MimeType string     `json:"mime_type"`
}

// RegistryActivity captures Windows registry operations
type RegistryActivity struct {
	KeysCreated   []RegistryOp `json:"keys_created,omitempty"`
	KeysModified  []RegistryOp `json:"keys_modified,omitempty"`
	KeysDeleted   []string     `json:"keys_deleted,omitempty"`
	KeysRead      []string     `json:"keys_read,omitempty"`
	AutorunEntries []RegistryOp `json:"autorun_entries,omitempty"`
}

// RegistryOp represents a registry operation
type RegistryOp struct {
	Key       string    `json:"key"`
	Value     string    `json:"value,omitempty"`
	Data      string    `json:"data,omitempty"`
	Type      string    `json:"type,omitempty"`
	Timestamp time.Time `json:"timestamp"`
}

// ProcessActivity captures process operations
type ProcessActivity struct {
	ProcessesCreated  []ProcessInfo `json:"processes_created,omitempty"`
	ProcessesInjected []ProcessInfo `json:"processes_injected,omitempty"`
	CommandLines      []string      `json:"command_lines,omitempty"`
	LoadedModules     []string      `json:"loaded_modules,omitempty"`
}

// ProcessInfo represents process information
type ProcessInfo struct {
	PID         int       `json:"pid"`
	Name        string    `json:"name"`
	Path        string    `json:"path"`
	CommandLine string    `json:"command_line"`
	ParentPID   int       `json:"parent_pid"`
	Timestamp   time.Time `json:"timestamp"`
}

// SignatureMatch represents a malware signature detection
type SignatureMatch struct {
	Name        string   `json:"name"`
	Severity    string   `json:"severity"` // low, medium, high, critical
	Category    string   `json:"category"` // trojan, ransomware, worm, etc.
	Family      string   `json:"family,omitempty"`
	Description string   `json:"description"`
	References  []string `json:"references,omitempty"`
}

// MITREMapping represents a MITRE ATT&CK technique mapping
type MITREMapping struct {
	TacticID    string `json:"tactic_id"`
	TacticName  string `json:"tactic_name"`
	TechniqueID string `json:"technique_id"`
	TechniqueName string `json:"technique_name"`
	Evidence    string `json:"evidence,omitempty"`
}

// IOC represents an Indicator of Compromise
type IOC struct {
	Type        string `json:"type"`  // hash, ip, domain, url, file_path, registry
	Value       string `json:"value"`
	Context     string `json:"context,omitempty"`
	Confidence  int    `json:"confidence"` // 0-100
}

// DetonationConfig holds detonation chamber configuration
type DetonationConfig struct {
	Enabled           bool          `yaml:"enabled" json:"enabled"`
	WatchDirs         []string      `yaml:"watch_dirs" json:"watch_dirs"`
	QuarantineDir     string        `yaml:"quarantine_dir" json:"quarantine_dir"`
	SandboxType       string        `yaml:"sandbox_type" json:"sandbox_type"` // docker, vm, native
	DockerImage       string        `yaml:"docker_image" json:"docker_image"`
	MaxConcurrent     int           `yaml:"max_concurrent" json:"max_concurrent"`
	DetonationTimeout time.Duration `yaml:"detonation_timeout" json:"detonation_timeout"`
	MaxFileSize       int64         `yaml:"max_file_size" json:"max_file_size"` // bytes
	SupportedTypes    []string      `yaml:"supported_types" json:"supported_types"`
	AutoSubmit        bool          `yaml:"auto_submit" json:"auto_submit"`
	RetainSamples     time.Duration `yaml:"retain_samples" json:"retain_samples"`
	EnableYara        bool          `yaml:"enable_yara" json:"enable_yara"`
	YaraRulesDir      string        `yaml:"yara_rules_dir" json:"yara_rules_dir"`
	PortalUpload      PortalUploadConfig `yaml:"portal_upload" json:"portal_upload"`
}

// PortalUploadConfig configures upload to AfterDark portal
type PortalUploadConfig struct {
	Enabled          bool          `yaml:"enabled" json:"enabled"`
	UploadSamples    bool          `yaml:"upload_samples" json:"upload_samples"`     // Upload actual malware samples
	UploadReports    bool          `yaml:"upload_reports" json:"upload_reports"`     // Upload analysis reports
	UploadIOCs       bool          `yaml:"upload_iocs" json:"upload_iocs"`           // Upload IOCs only
	MinThreatScore   int           `yaml:"min_threat_score" json:"min_threat_score"` // Only upload if score >= this
	BatchSize        int           `yaml:"batch_size" json:"batch_size"`
	BatchInterval    time.Duration `yaml:"batch_interval" json:"batch_interval"`
}
