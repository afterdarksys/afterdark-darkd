package memscan

import (
	"encoding/binary"
	"github.com/afterdarksys/afterdark-darkd/internal/models"
	"math"
	"testing"
)

func TestMemoryEntropy(t *testing.T) {
	uniform := make([]byte, 256)
	for i := range uniform {
		uniform[i] = byte(i)
	}
	for _, tc := range []struct {
		data []byte
		want float64
	}{{nil, 0}, {make([]byte, 256), 0}, {[]byte{1, 2, 1, 2}, 1}, {uniform, 8}} {
		if got := calculateEntropy(tc.data); math.Abs(got-tc.want) > 1e-9 {
			t.Fatalf("entropy=%v want %v", got, tc.want)
		}
	}
}
func TestExecutableHeaders(t *testing.T) {
	pe := make([]byte, 128)
	copy(pe, "MZ")
	binary.LittleEndian.PutUint32(pe[0x3c:], 64)
	copy(pe[64:], []byte{'P', 'E', 0, 0})
	if !containsPEHeader(pe) {
		t.Fatal("valid PE not recognized")
	}
	// e_lfanew is a 32-bit offset; do not truncate it to 16 bits.
	binary.LittleEndian.PutUint32(pe[0x3c:], 65536+64)
	if containsPEHeader(pe) {
		t.Fatal("out of bounds PE offset accepted")
	}
	if containsPEHeader([]byte("MZ")) {
		t.Fatal("truncated header accepted")
	}
	if !containsELFHeader([]byte{0x7f, 'E', 'L', 'F'}) || containsELFHeader([]byte("ELF")) {
		t.Fatal("ELF magic parsing")
	}
}
func TestRegionClassification(t *testing.T) {
	s := New(&models.MemoryScannerConfig{MaxConcurrentScans: 1})
	for _, tc := range []struct {
		r    models.MemoryRegion
		want bool
	}{
		{models.MemoryRegion{Protection: models.ProtectionRWX}, true},
		{models.MemoryRegion{IsExecutable: true, IsUnbacked: true}, true},
		{models.MemoryRegion{IsExecutable: true, Entropy: 7.9}, true},
		{models.MemoryRegion{Protection: models.ProtectionRX, Type: models.RegionTypeImage, MappedFile: "image"}, false},
	} {
		if got := s.isSuspiciousRegion(tc.r); got != tc.want {
			t.Fatalf("region %+v = %v", tc.r, got)
		}
	}
}
func TestThreatScoreAndLevel(t *testing.T) {
	s := New(&models.MemoryScannerConfig{MaxConcurrentScans: 1})
	for _, tc := range []struct {
		r     models.MemoryScanResult
		score float64
		level string
	}{
		{models.MemoryScanResult{}, 0, "clean"},
		{models.MemoryScanResult{Detections: []models.MemoryDetection{{Confidence: 0.5}}, SuspiciousRegions: []models.MemoryRegion{{}}}, 20, "low"},
		{models.MemoryScanResult{Detections: []models.MemoryDetection{{Confidence: 1}, {Confidence: 1}, {Confidence: 1}, {Confidence: 1}}}, 100, "critical"},
	} {
		got := s.calculateThreatScore(&tc.r)
		if got != tc.score || s.determineThreatLevel(got) != tc.level {
			t.Fatalf("score/level %v/%s", got, s.determineThreatLevel(got))
		}
	}
}
func TestShellcodeRequiresCorroboration(t *testing.T) {
	s := New(&models.MemoryScannerConfig{MaxConcurrentScans: 1})
	// A syscall instruction occurs in ordinary software and is not sufficient evidence.
	if s.detectShellcode([]byte{0x48, 0xc7, 0xc0, 0x3c, 0, 0, 0, 0x0f, 0x05}, models.MemoryRegion{}) != nil {
		t.Fatal("isolated syscall classified as shellcode")
	}
}
