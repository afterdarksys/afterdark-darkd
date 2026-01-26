package models

import "time"

// MemoryScanResult contains the results of scanning a process's memory
type MemoryScanResult struct {
	PID          int           `json:"pid"`
	ProcessName  string        `json:"process_name"`
	ProcessPath  string        `json:"process_path"`
	Username     string        `json:"username,omitempty"`
	ScanTime     time.Time     `json:"scan_time"`
	ScanDuration time.Duration `json:"scan_duration_ms"`

	// Findings
	Detections        []MemoryDetection `json:"detections"`
	SuspiciousRegions []MemoryRegion    `json:"suspicious_regions"`
	YARAMatches       []YARAMatch       `json:"yara_matches"`

	// Summary
	ThreatScore       float64 `json:"threat_score"`
	ThreatLevel       string  `json:"threat_level"` // "clean", "suspicious", "malicious"
	InjectionDetected bool    `json:"injection_detected"`
	ShellcodeFound    bool    `json:"shellcode_found"`
	HollowingDetected bool    `json:"hollowing_detected"`

	// Statistics
	TotalRegions    int   `json:"total_regions"`
	ScannedRegions  int   `json:"scanned_regions"`
	TotalMemorySize int64 `json:"total_memory_size"`
	ScannedSize     int64 `json:"scanned_size"`
}

// MemoryRegion represents a memory region in a process
type MemoryRegion struct {
	BaseAddress uint64  `json:"base_address"`
	Size        uint64  `json:"size"`
	Protection  string  `json:"protection"` // "RWX", "RW", "RX", "R", etc.
	Type        string  `json:"type"`       // "Image", "Mapped", "Private", "Stack", "Heap"
	State       string  `json:"state"`      // "Commit", "Reserve", "Free"
	Entropy     float64 `json:"entropy"`
	ContainsPE  bool    `json:"contains_pe"`
	ContainsELF bool    `json:"contains_elf"`
	MappedFile  string  `json:"mapped_file,omitempty"`

	// Analysis flags
	IsExecutable     bool `json:"is_executable"`
	IsWritable       bool `json:"is_writable"`
	IsUnbacked       bool `json:"is_unbacked"` // Executable without backing file
	HasAnomalousCode bool `json:"has_anomalous_code"`
}

// MemoryDetection represents a specific threat detection in memory
type MemoryDetection struct {
	Type        string   `json:"type"` // "shellcode", "injection", "hollow", "pe_header", "hook"
	Description string   `json:"description"`
	Address     uint64   `json:"address"`
	Size        uint64   `json:"size"`
	Confidence  float64  `json:"confidence"`   // 0.0-1.0
	TechniqueID string   `json:"technique_id"` // MITRE ATT&CK ID
	Indicators  []string `json:"indicators"`
	Severity    string   `json:"severity"` // "low", "medium", "high", "critical"
	RawData     []byte   `json:"-"`        // Sample bytes (not serialized)
}

// YARAMatch represents a YARA rule match in memory
type YARAMatch struct {
	Rule      string            `json:"rule"`
	Namespace string            `json:"namespace"`
	Strings   []YARAString      `json:"strings"`
	Meta      map[string]string `json:"meta"`
	Address   uint64            `json:"address"`
}

// YARAString represents a matched YARA string
type YARAString struct {
	Name   string `json:"name"`
	Offset uint64 `json:"offset"`
	Data   string `json:"data"` // Hex-encoded
	Length int    `json:"length"`
}

// ShellcodeSignature defines characteristics to detect shellcode
type ShellcodeSignature struct {
	Name        string
	Description string
	Patterns    [][]byte // Byte patterns to search for
	Opcodes     []byte   // x86/x64 opcode sequences
	MinSize     int
	MaxSize     int
	Confidence  float64
}

// CommonShellcodeSignatures contains signatures for common shellcode patterns
var CommonShellcodeSignatures = []ShellcodeSignature{
	{
		Name:        "nop_sled",
		Description: "NOP sled (0x90 sequence)",
		Patterns:    [][]byte{{0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90}},
		MinSize:     8,
		Confidence:  0.3,
	},
	{
		Name:        "syscall_x64",
		Description: "x64 syscall instruction",
		Patterns:    [][]byte{{0x0f, 0x05}}, // syscall
		Confidence:  0.4,
	},
	{
		Name:        "int80_x86",
		Description: "x86 int 0x80 syscall",
		Patterns:    [][]byte{{0xcd, 0x80}}, // int 0x80
		Confidence:  0.4,
	},
	{
		Name:        "call_pop",
		Description: "Call/pop (position-independent code)",
		Patterns:    [][]byte{{0xe8, 0x00, 0x00, 0x00, 0x00, 0x58}}, // call $+5; pop eax
		Confidence:  0.6,
	},
	{
		Name:        "fs_gs_access",
		Description: "TEB/PEB access via segment registers",
		Patterns: [][]byte{
			{0x64, 0xa1}, // mov eax, fs:[...]
			{0x65, 0x48}, // gs: prefix (x64)
		},
		Confidence: 0.5,
	},
	{
		Name:        "kernel32_hash",
		Description: "API hashing (GetProcAddress pattern)",
		Patterns: [][]byte{
			{0x6b, 0x65, 0x72, 0x6e, 0x65, 0x6c, 0x33, 0x32}, // "kernel32"
		},
		Confidence: 0.4,
	},
	{
		Name:        "ws2_32",
		Description: "Winsock library reference",
		Patterns: [][]byte{
			{0x77, 0x73, 0x32, 0x5f, 0x33, 0x32}, // "ws2_32"
		},
		Confidence: 0.5,
	},
	{
		Name:        "meterpreter_stage",
		Description: "Meterpreter staging pattern",
		Patterns: [][]byte{
			{0xfc, 0xe8}, // cld; call
		},
		MinSize:    200,
		Confidence: 0.7,
	},
}

// InjectionType defines types of process injection
type InjectionType string

const (
	InjectionClassicDLL    InjectionType = "classic_dll"
	InjectionReflective    InjectionType = "reflective_dll"
	InjectionProcessHollow InjectionType = "process_hollowing"
	InjectionThreadHijack  InjectionType = "thread_hijack"
	InjectionAPCQueue      InjectionType = "apc_queue"
	InjectionAtomBombing   InjectionType = "atom_bombing"
	InjectionProcessDopple InjectionType = "process_doppelganging"
)

// InjectionIndicator represents evidence of process injection
type InjectionIndicator struct {
	Type        InjectionType `json:"type"`
	Description string        `json:"description"`
	Evidence    []string      `json:"evidence"`
	Confidence  float64       `json:"confidence"`
	TechniqueID string        `json:"technique_id"` // MITRE ATT&CK
}

// MemoryScanEvent represents a memory scan detection event
type MemoryScanEvent struct {
	Timestamp      time.Time         `json:"timestamp"`
	AgentID        string            `json:"agent_id"`
	Hostname       string            `json:"hostname"`
	Result         *MemoryScanResult `json:"result"`
	Action         string            `json:"action"`   // "detected", "quarantined", "terminated"
	Severity       string            `json:"severity"` // "low", "medium", "high", "critical"
	MITRETechnique string            `json:"mitre_technique"`
}

// ScanProcessInfo contains information about a process for scanning
type ScanProcessInfo struct {
	PID         int       `json:"pid"`
	PPID        int       `json:"ppid"`
	Name        string    `json:"name"`
	Path        string    `json:"path"`
	CommandLine string    `json:"command_line"`
	Username    string    `json:"username"`
	StartTime   time.Time `json:"start_time"`
	IsSystem    bool      `json:"is_system"`
	HasNetwork  bool      `json:"has_network"` // Has network connections
}

// Memory protection constants
const (
	ProtectionRead    = "R"
	ProtectionWrite   = "W"
	ProtectionExecute = "X"
	ProtectionRW      = "RW"
	ProtectionRX      = "RX"
	ProtectionRWX     = "RWX"
)

// Memory region types
const (
	RegionTypeImage   = "Image"
	RegionTypeMapped  = "Mapped"
	RegionTypePrivate = "Private"
	RegionTypeStack   = "Stack"
	RegionTypeHeap    = "Heap"
)

// Detection types
const (
	DetectionShellcode       = "shellcode"
	DetectionInjection       = "injection"
	DetectionHollowing       = "hollowing"
	DetectionPEHeader        = "pe_header"
	DetectionELFHeader       = "elf_header"
	DetectionHook            = "hook"
	DetectionUnbackedCode    = "unbacked_code"
	DetectionRWXRegion       = "rwx_region"
	DetectionSuspiciousAlloc = "suspicious_alloc"
)

// MITRE ATT&CK technique IDs for memory-related attacks
const (
	MITRET1055    = "T1055"     // Process Injection
	MITRET1055001 = "T1055.001" // Dynamic-link Library Injection
	MITRET1055002 = "T1055.002" // Portable Executable Injection
	MITRET1055003 = "T1055.003" // Thread Execution Hijacking
	MITRET1055004 = "T1055.004" // Asynchronous Procedure Call
	MITRET1055012 = "T1055.012" // Process Hollowing
	MITRET1620    = "T1620"     // Reflective Code Loading
	MITRET1574    = "T1574"     // Hijack Execution Flow
)
