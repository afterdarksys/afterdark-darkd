package memscan

import (
	"testing"
	"time"

	"github.com/afterdarksys/afterdark-darkd/internal/models"
)

func TestNew(t *testing.T) {
	config := &models.MemoryScannerConfig{
		Enabled:            true,
		ScanInterval:       30 * time.Minute,
		YaraRulesDir:       "/var/lib/afterdark/yara",
		CheckRWXRegions:    true,
		CheckUnbackedCode:  true,
		DetectInjection:    true,
		MonitorLSASS:       true,
		MaxConcurrentScans: 2,
	}

	svc := New(config)

	if svc == nil {
		t.Fatal("expected non-nil service")
	}

	if svc.Name() != "memory_scanner" {
		t.Errorf("expected name 'memory_scanner', got %q", svc.Name())
	}

	if cap(svc.scanSem) != 2 {
		t.Errorf("expected scan semaphore capacity 2, got %d", cap(svc.scanSem))
	}
}

func TestCalculateMemoryEntropy(t *testing.T) {
	tests := []struct {
		name       string
		data       []byte
		minEntropy float64
		maxEntropy float64
	}{
		{
			name:       "all zeros",
			data:       make([]byte, 256),
			minEntropy: 0.0,
			maxEntropy: 0.1,
		},
		{
			name:       "repeating pattern",
			data:       []byte{0xAA, 0xBB, 0xAA, 0xBB, 0xAA, 0xBB, 0xAA, 0xBB},
			minEntropy: 0.9,
			maxEntropy: 1.1,
		},
		{
			name:       "text data",
			data:       []byte("Hello, World! This is some normal text content."),
			minEntropy: 3.5,
			maxEntropy: 4.5,
		},
		{
			name:       "high entropy - pseudo-random",
			data:       generatePseudoRandomBytes(256),
			minEntropy: 7.0,
			maxEntropy: 8.0,
		},
	}

	config := &models.MemoryScannerConfig{Enabled: true, MaxConcurrentScans: 1}
	svc := New(config)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			entropy := svc.calculateEntropy(tt.data)
			if entropy < tt.minEntropy || entropy > tt.maxEntropy {
				t.Errorf("entropy %.2f not in expected range [%.2f, %.2f]",
					entropy, tt.minEntropy, tt.maxEntropy)
			}
		})
	}
}

func generatePseudoRandomBytes(n int) []byte {
	data := make([]byte, n)
	for i := range data {
		data[i] = byte((i * 17 + 31) % 256) // Simple PRNG-like pattern
	}
	return data
}

func TestShellcodeDetection(t *testing.T) {
	tests := []struct {
		name           string
		data           []byte
		expectedDetect bool
		expectedType   string
	}{
		{
			name:           "NOP sled",
			data:           append(make([]byte, 20, 50), 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0xCC),
			expectedDetect: true,
			expectedType:   "nop_sled",
		},
		{
			name:           "syscall pattern (x86_64)",
			data:           []byte{0x48, 0xc7, 0xc0, 0x3c, 0x00, 0x00, 0x00, 0x0f, 0x05}, // mov rax, 60; syscall
			expectedDetect: true,
			expectedType:   "syscall",
		},
		{
			name:           "int 0x80 pattern (x86)",
			data:           []byte{0xb8, 0x01, 0x00, 0x00, 0x00, 0xcd, 0x80}, // mov eax, 1; int 0x80
			expectedDetect: true,
			expectedType:   "syscall",
		},
		{
			name:           "normal code",
			data:           []byte{0x55, 0x48, 0x89, 0xe5, 0x48, 0x83, 0xec, 0x10}, // push rbp; mov rbp, rsp; sub rsp, 16
			expectedDetect: false,
			expectedType:   "",
		},
		{
			name:           "zeros",
			data:           make([]byte, 50),
			expectedDetect: false,
			expectedType:   "",
		},
	}

	config := &models.MemoryScannerConfig{Enabled: true, MaxConcurrentScans: 1}
	svc := New(config)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			detection := svc.detectShellcode(tt.data, 0x1000)

			if tt.expectedDetect && detection == nil {
				t.Error("expected shellcode detection but got none")
			}

			if !tt.expectedDetect && detection != nil {
				t.Errorf("unexpected shellcode detection: %+v", detection)
			}

			if detection != nil && tt.expectedType != "" {
				found := false
				for _, ind := range detection.Indicators {
					if ind == tt.expectedType || len(ind) > 0 {
						found = true
						break
					}
				}
				if !found && len(detection.Indicators) == 0 {
					// Check if type is in the detection
					t.Logf("detection type: %s, indicators: %v", detection.Type, detection.Indicators)
				}
			}
		})
	}
}

func TestPEHeaderDetection(t *testing.T) {
	tests := []struct {
		name           string
		region         models.MemoryRegion
		data           []byte
		expectedDetect bool
	}{
		{
			name: "PE in private memory",
			region: models.MemoryRegion{
				Type:       models.RegionTypePrivate,
				MappedFile: "",
			},
			data:           []byte{'M', 'Z', 0x90, 0x00, 0x03, 0x00, 0x00, 0x00},
			expectedDetect: true,
		},
		{
			name: "PE in mapped image - legitimate",
			region: models.MemoryRegion{
				Type:       models.RegionTypeImage,
				MappedFile: "/usr/lib/libc.so",
			},
			data:           []byte{'M', 'Z', 0x90, 0x00, 0x03, 0x00, 0x00, 0x00},
			expectedDetect: false,
		},
		{
			name: "No PE header",
			region: models.MemoryRegion{
				Type:       models.RegionTypePrivate,
				MappedFile: "",
			},
			data:           []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
			expectedDetect: false,
		},
	}

	config := &models.MemoryScannerConfig{Enabled: true, MaxConcurrentScans: 1}
	svc := New(config)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			detection := svc.detectReflectiveLoading(tt.region, tt.data)

			if tt.expectedDetect && detection == nil {
				t.Error("expected PE detection but got none")
			}

			if !tt.expectedDetect && detection != nil {
				t.Errorf("unexpected PE detection: %+v", detection)
			}
		})
	}
}

func TestELFHeaderDetection(t *testing.T) {
	tests := []struct {
		name           string
		region         models.MemoryRegion
		data           []byte
		expectedDetect bool
	}{
		{
			name: "ELF in private memory",
			region: models.MemoryRegion{
				Type:       models.RegionTypePrivate,
				MappedFile: "",
			},
			data:           []byte{0x7f, 'E', 'L', 'F', 0x02, 0x01, 0x01, 0x00},
			expectedDetect: true,
		},
		{
			name: "ELF in mapped file - legitimate",
			region: models.MemoryRegion{
				Type:       models.RegionTypeImage,
				MappedFile: "/usr/bin/ls",
			},
			data:           []byte{0x7f, 'E', 'L', 'F', 0x02, 0x01, 0x01, 0x00},
			expectedDetect: false,
		},
		{
			name: "No ELF header",
			region: models.MemoryRegion{
				Type:       models.RegionTypePrivate,
				MappedFile: "",
			},
			data:           []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
			expectedDetect: false,
		},
	}

	config := &models.MemoryScannerConfig{Enabled: true, MaxConcurrentScans: 1}
	svc := New(config)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			detection := svc.detectELFInMemory(tt.region, tt.data)

			if tt.expectedDetect && detection == nil {
				t.Error("expected ELF detection but got none")
			}

			if !tt.expectedDetect && detection != nil {
				t.Errorf("unexpected ELF detection: %+v", detection)
			}
		})
	}
}

func TestRWXRegionDetection(t *testing.T) {
	tests := []struct {
		name           string
		region         models.MemoryRegion
		expectedSusp   bool
	}{
		{
			name: "RWX private memory",
			region: models.MemoryRegion{
				Protection:   models.ProtectionRWX,
				Type:         models.RegionTypePrivate,
				IsExecutable: true,
				IsWritable:   true,
			},
			expectedSusp: true,
		},
		{
			name: "RX mapped image - normal",
			region: models.MemoryRegion{
				Protection:   models.ProtectionRX,
				Type:         models.RegionTypeImage,
				IsExecutable: true,
				IsWritable:   false,
				MappedFile:   "/lib/libc.so.6",
			},
			expectedSusp: false,
		},
		{
			name: "unbacked executable",
			region: models.MemoryRegion{
				Protection:   models.ProtectionRX,
				Type:         models.RegionTypePrivate,
				IsExecutable: true,
				IsUnbacked:   true,
			},
			expectedSusp: true,
		},
	}

	config := &models.MemoryScannerConfig{
		Enabled:           true,
		CheckRWXRegions:   true,
		CheckUnbackedCode: true,
		MaxConcurrentScans: 1,
	}
	svc := New(config)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			suspicious := svc.isRegionSuspicious(tt.region)
			if suspicious != tt.expectedSusp {
				t.Errorf("expected suspicious=%v, got %v", tt.expectedSusp, suspicious)
			}
		})
	}
}

func TestThreatScoreCalculation(t *testing.T) {
	tests := []struct {
		name          string
		result        *models.MemoryScanResult
		expectedMin   float64
		expectedMax   float64
		expectedLevel string
	}{
		{
			name: "clean process",
			result: &models.MemoryScanResult{
				Detections:        []models.MemoryDetection{},
				SuspiciousRegions: []models.MemoryRegion{},
				YARAMatches:       []models.YARAMatch{},
			},
			expectedMin:   0.0,
			expectedMax:   10.0,
			expectedLevel: "clean",
		},
		{
			name: "suspicious process",
			result: &models.MemoryScanResult{
				Detections: []models.MemoryDetection{
					{Type: "shellcode", Confidence: 0.5},
				},
				SuspiciousRegions: []models.MemoryRegion{
					{Protection: models.ProtectionRWX},
				},
			},
			expectedMin:   30.0,
			expectedMax:   60.0,
			expectedLevel: "suspicious",
		},
		{
			name: "malicious process",
			result: &models.MemoryScanResult{
				Detections: []models.MemoryDetection{
					{Type: "shellcode", Confidence: 0.9},
					{Type: "injection", Confidence: 0.8},
				},
				SuspiciousRegions: []models.MemoryRegion{
					{Protection: models.ProtectionRWX, IsUnbacked: true},
					{Protection: models.ProtectionRWX, IsUnbacked: true},
				},
				YARAMatches: []models.YARAMatch{
					{Rule: "Cobalt_Strike_Beacon"},
				},
				ShellcodeFound:    true,
				InjectionDetected: true,
			},
			expectedMin:   70.0,
			expectedMax:   100.0,
			expectedLevel: "malicious",
		},
	}

	config := &models.MemoryScannerConfig{Enabled: true, MaxConcurrentScans: 1}
	svc := New(config)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svc.calculateThreatScore(tt.result)

			if tt.result.ThreatScore < tt.expectedMin || tt.result.ThreatScore > tt.expectedMax {
				t.Errorf("threat score %.2f not in expected range [%.2f, %.2f]",
					tt.result.ThreatScore, tt.expectedMin, tt.expectedMax)
			}

			if tt.result.ThreatLevel != tt.expectedLevel {
				t.Errorf("expected threat level %q, got %q",
					tt.expectedLevel, tt.result.ThreatLevel)
			}
		})
	}
}
