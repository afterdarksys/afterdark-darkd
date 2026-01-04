package detonation

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"io"
	"math"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/afterdarksys/afterdark-darkd/internal/models"
)

// FileAnalyzer provides static analysis capabilities for files
type FileAnalyzer struct {
	yaraRulesDir string
	enableYara   bool
}

// NewFileAnalyzer creates a new file analyzer
func NewFileAnalyzer(yaraRulesDir string, enableYara bool) *FileAnalyzer {
	return &FileAnalyzer{
		yaraRulesDir: yaraRulesDir,
		enableYara:   enableYara,
	}
}

// AnalyzeFile performs static analysis on a file
func (a *FileAnalyzer) AnalyzeFile(path string) (*models.DetonationSample, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()

	stat, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("failed to stat file: %w", err)
	}

	// Calculate hashes
	hashes, err := a.calculateHashes(file)
	if err != nil {
		return nil, fmt.Errorf("failed to calculate hashes: %w", err)
	}

	// Reset file position
	if _, err := file.Seek(0, 0); err != nil {
		return nil, fmt.Errorf("failed to seek file: %w", err)
	}

	// Detect MIME type
	mimeType, err := a.detectMimeType(file)
	if err != nil {
		mimeType = "application/octet-stream"
	}

	sample := &models.DetonationSample{
		FileName: filepath.Base(path),
		FileSize: stat.Size(),
		FilePath: path,
		MimeType: mimeType,
		Hashes:   *hashes,
		Status:   models.DetonationStatusPending,
		Verdict:  models.VerdictUnknown,
	}

	return sample, nil
}

// PerformStaticAnalysis performs detailed static analysis
func (a *FileAnalyzer) PerformStaticAnalysis(path string) (*models.StaticAnalysis, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()

	analysis := &models.StaticAnalysis{}

	// Detect file type from magic bytes
	magic, fileType, err := a.detectMagic(file)
	if err == nil {
		analysis.Magic = magic
		analysis.FileType = fileType
	}

	// Reset file position
	if _, err := file.Seek(0, 0); err != nil {
		return nil, fmt.Errorf("failed to seek file: %w", err)
	}

	// Calculate entropy
	entropy, err := a.calculateEntropy(file)
	if err == nil {
		analysis.Entropy = entropy
		// High entropy (> 7.0) often indicates packing/encryption
		analysis.IsPacked = entropy > 7.0
		analysis.IsEncrypted = entropy > 7.5
	}

	// Reset and extract strings
	if _, err := file.Seek(0, 0); err != nil {
		return nil, fmt.Errorf("failed to seek file: %w", err)
	}

	strings, err := a.extractSuspiciousStrings(file)
	if err == nil {
		analysis.Strings = strings
	}

	// TODO: Add PE/ELF parsing for imports, exports, sections
	// TODO: Add YARA rule matching

	return analysis, nil
}

// calculateHashes computes multiple hash types for a file
func (a *FileAnalyzer) calculateHashes(r io.Reader) (*models.FileHashes, error) {
	md5Hash := md5.New()
	sha1Hash := sha1.New()
	sha256Hash := sha256.New()
	sha512Hash := sha512.New()

	// Multi-writer to compute all hashes in single pass
	multiWriter := io.MultiWriter(md5Hash, sha1Hash, sha256Hash, sha512Hash)

	if _, err := io.Copy(multiWriter, r); err != nil {
		return nil, err
	}

	return &models.FileHashes{
		MD5:    hex.EncodeToString(md5Hash.Sum(nil)),
		SHA1:   hex.EncodeToString(sha1Hash.Sum(nil)),
		SHA256: hex.EncodeToString(sha256Hash.Sum(nil)),
		SHA512: hex.EncodeToString(sha512Hash.Sum(nil)),
	}, nil
}

// detectMimeType detects the MIME type of a file
func (a *FileAnalyzer) detectMimeType(file *os.File) (string, error) {
	// Read first 512 bytes for detection
	buffer := make([]byte, 512)
	n, err := file.Read(buffer)
	if err != nil && err != io.EOF {
		return "", err
	}

	return http.DetectContentType(buffer[:n]), nil
}

// detectMagic reads magic bytes and returns file type
func (a *FileAnalyzer) detectMagic(file *os.File) (string, string, error) {
	buffer := make([]byte, 16)
	n, err := file.Read(buffer)
	if err != nil && err != io.EOF {
		return "", "", err
	}

	if n < 2 {
		return "", "unknown", nil
	}

	magicHex := hex.EncodeToString(buffer[:n])

	// Common magic signatures
	switch {
	case strings.HasPrefix(magicHex, "4d5a"): // MZ
		return "MZ", "PE/EXE", nil
	case strings.HasPrefix(magicHex, "7f454c46"): // ELF
		return "7F454C46", "ELF", nil
	case strings.HasPrefix(magicHex, "cafebabe"): // Java class
		return "CAFEBABE", "Java Class", nil
	case strings.HasPrefix(magicHex, "504b0304"): // PK (ZIP/JAR/APK/DOCX)
		return "PK", "ZIP Archive", nil
	case strings.HasPrefix(magicHex, "25504446"): // %PDF
		return "%PDF", "PDF Document", nil
	case strings.HasPrefix(magicHex, "d0cf11e0"): // OLE compound
		return "D0CF11E0", "OLE Document", nil
	case strings.HasPrefix(magicHex, "ffd8ff"): // JPEG
		return "FFD8FF", "JPEG Image", nil
	case strings.HasPrefix(magicHex, "89504e47"): // PNG
		return "89504E47", "PNG Image", nil
	case strings.HasPrefix(magicHex, "1f8b08"): // GZIP
		return "1F8B08", "GZIP Archive", nil
	case strings.HasPrefix(magicHex, "52617221"): // RAR
		return "Rar!", "RAR Archive", nil
	case strings.HasPrefix(magicHex, "377abcaf"): // 7z
		return "377ABCAF", "7-Zip Archive", nil
	case strings.HasPrefix(magicHex, "feedface") || strings.HasPrefix(magicHex, "cefaedfe"): // Mach-O
		return magicHex[:8], "Mach-O", nil
	case strings.HasPrefix(magicHex, "feedfacf") || strings.HasPrefix(magicHex, "cffaedfe"): // Mach-O 64
		return magicHex[:8], "Mach-O 64-bit", nil
	default:
		// Check for script shebangs
		if strings.HasPrefix(string(buffer[:n]), "#!") {
			return "#!", "Script", nil
		}
		return magicHex[:8], "unknown", nil
	}
}

// calculateEntropy calculates Shannon entropy of file
func (a *FileAnalyzer) calculateEntropy(r io.Reader) (float64, error) {
	// Count byte frequencies
	freq := make([]int64, 256)
	var total int64

	buffer := make([]byte, 32*1024)
	for {
		n, err := r.Read(buffer)
		if n > 0 {
			for _, b := range buffer[:n] {
				freq[b]++
				total++
			}
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return 0, err
		}
	}

	if total == 0 {
		return 0, nil
	}

	// Calculate entropy
	var entropy float64
	for _, count := range freq {
		if count > 0 {
			p := float64(count) / float64(total)
			entropy -= p * math.Log2(p)
		}
	}

	return entropy, nil
}

// extractSuspiciousStrings finds potentially malicious strings in the file
func (a *FileAnalyzer) extractSuspiciousStrings(r io.Reader) ([]models.SuspiciousString, error) {
	var suspicious []models.SuspiciousString

	// Read entire file (limit to first 10MB for performance)
	data, err := io.ReadAll(io.LimitReader(r, 10*1024*1024))
	if err != nil {
		return nil, err
	}

	content := string(data)
	var offset int64

	// Look for URLs
	urlPatterns := []string{"http://", "https://", "ftp://"}
	for _, pattern := range urlPatterns {
		idx := 0
		for {
			pos := strings.Index(content[idx:], pattern)
			if pos == -1 {
				break
			}
			// Extract URL (until whitespace or control char)
			start := idx + pos
			end := start
			for end < len(content) && content[end] > ' ' && content[end] < 127 {
				end++
			}
			url := content[start:end]
			if len(url) > len(pattern)+3 { // Must have more than just protocol
				suspicious = append(suspicious, models.SuspiciousString{
					Value:    truncateString(url, 200),
					Category: "url",
					Offset:   offset + int64(start),
				})
			}
			idx = end
		}
	}

	// Look for IP addresses (simple pattern)
	ipPattern := func(s string, idx int) (string, int) {
		// Very basic IP detection
		for i := idx; i < len(s)-7; i++ {
			if s[i] >= '0' && s[i] <= '9' {
				// Check for IP-like pattern
				j := i
				dots := 0
				for j < len(s) && ((s[j] >= '0' && s[j] <= '9') || s[j] == '.') {
					if s[j] == '.' {
						dots++
					}
					j++
				}
				if dots == 3 && j-i >= 7 && j-i <= 15 {
					return s[i:j], j
				}
			}
		}
		return "", -1
	}

	idx := 0
	for {
		ip, nextIdx := ipPattern(content, idx)
		if nextIdx == -1 {
			break
		}
		suspicious = append(suspicious, models.SuspiciousString{
			Value:    ip,
			Category: "ip",
			Offset:   int64(idx),
		})
		idx = nextIdx
		if len(suspicious) > 100 {
			break // Limit results
		}
	}

	// Look for suspicious Windows API calls
	suspiciousAPIs := []string{
		"VirtualAlloc", "VirtualProtect", "WriteProcessMemory", "CreateRemoteThread",
		"NtUnmapViewOfSection", "SetThreadContext", "ResumeThread",
		"LoadLibrary", "GetProcAddress", "ShellExecute", "WinExec",
		"URLDownloadToFile", "InternetOpen", "HttpSendRequest",
		"RegSetValue", "RegCreateKey", "CreateService", "StartService",
		"CryptEncrypt", "CryptDecrypt", "BCryptEncrypt",
	}

	for _, api := range suspiciousAPIs {
		if idx := strings.Index(content, api); idx != -1 {
			suspicious = append(suspicious, models.SuspiciousString{
				Value:    api,
				Category: "api_call",
				Offset:   int64(idx),
			})
		}
	}

	// Look for registry paths
	registryPaths := []string{
		"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
		"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
		"HKEY_LOCAL_MACHINE",
		"HKEY_CURRENT_USER",
	}

	for _, reg := range registryPaths {
		if idx := strings.Index(content, reg); idx != -1 {
			suspicious = append(suspicious, models.SuspiciousString{
				Value:    reg,
				Category: "registry",
				Offset:   int64(idx),
			})
		}
	}

	return suspicious, nil
}

func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}
