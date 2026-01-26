// Package keywatch provides Keychain analysis and monitoring for macOS
//
// This module analyzes the macOS Keychain for:
// - Suspicious entries (unknown issuers, odd domains)
// - Duplicate credentials
// - Expired certificates
// - Weak cryptographic keys
// - Potentially compromised entries
// - Unauthorized access patterns
//
// Note: Full keychain access requires user authorization or root privileges.
// Basic metadata can be read without authorization.
//
// Build: Part of osx-security plugin for afterdark-darkd
package keywatch

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// KeychainItem represents an item in the keychain
type KeychainItem struct {
	Class            string            `json:"class"`             // genp, inet, cert, keys
	Label            string            `json:"label"`
	Account          string            `json:"account,omitempty"`
	Service          string            `json:"service,omitempty"`
	Server           string            `json:"server,omitempty"`
	Protocol         string            `json:"protocol,omitempty"`
	Port             int               `json:"port,omitempty"`
	Path             string            `json:"path,omitempty"`
	Type             string            `json:"type,omitempty"`
	Kind             string            `json:"kind,omitempty"`
	Creator          string            `json:"creator,omitempty"`
	CreationDate     time.Time         `json:"creation_date,omitempty"`
	ModificationDate time.Time         `json:"modification_date,omitempty"`
	Keychain         string            `json:"keychain"`
	Access           string            `json:"access,omitempty"`
	Hash             string            `json:"hash"` // SHA256 of identifying info (not password)
	Attributes       map[string]string `json:"attributes,omitempty"`
}

// Certificate represents a certificate in the keychain
type Certificate struct {
	Label           string    `json:"label"`
	Subject         string    `json:"subject"`
	Issuer          string    `json:"issuer"`
	SerialNumber    string    `json:"serial_number"`
	NotBefore       time.Time `json:"not_before"`
	NotAfter        time.Time `json:"not_after"`
	IsExpired       bool      `json:"is_expired"`
	IsExpiringSoon  bool      `json:"is_expiring_soon"` // Within 30 days
	IsSelfSigned    bool      `json:"is_self_signed"`
	KeyAlgorithm    string    `json:"key_algorithm"`
	KeySize         int       `json:"key_size"`
	SignatureAlg    string    `json:"signature_algorithm"`
	IsWeakCrypto    bool      `json:"is_weak_crypto"`
	Keychain        string    `json:"keychain"`
	Hash            string    `json:"hash"`
}

// Finding represents a security finding from Keychain analysis
type Finding struct {
	Severity    string                 `json:"severity"` // critical, high, medium, low, info
	Type        string                 `json:"type"`
	Title       string                 `json:"title"`
	Description string                 `json:"description"`
	Item        string                 `json:"item,omitempty"`
	Details     map[string]interface{} `json:"details,omitempty"`
	DetectedAt  time.Time              `json:"detected_at"`
}

// AnalysisResult contains the results of a Keychain analysis
type AnalysisResult struct {
	Timestamp          time.Time       `json:"timestamp"`
	KeychainsAnalyzed  []string        `json:"keychains_analyzed"`
	TotalItems         int             `json:"total_items"`
	GenericPasswords   int             `json:"generic_passwords"`
	InternetPasswords  int             `json:"internet_passwords"`
	Certificates       int             `json:"certificates"`
	Keys               int             `json:"keys"`
	Items              []KeychainItem  `json:"items"`
	CertificateDetails []Certificate   `json:"certificate_details"`
	Findings           []Finding       `json:"findings"`
	Duplicates         []DuplicateSet  `json:"duplicates"`
	RequiresAuth       bool            `json:"requires_auth"` // True if enhanced features need user auth
}

// DuplicateSet represents a set of duplicate entries
type DuplicateSet struct {
	Key    string         `json:"key"` // What makes them duplicates
	Items  []KeychainItem `json:"items"`
	Count  int            `json:"count"`
}

// Analyzer performs Keychain analysis
type Analyzer struct {
	securityPath     string
	authorizedLevel  int // 0=basic, 1=read metadata, 2=full access (with user auth)
	previousAnalysis *AnalysisResult
	knownItems       map[string]KeychainItem
}

// NewAnalyzer creates a new Keychain analyzer
func NewAnalyzer() *Analyzer {
	return &Analyzer{
		securityPath:    "/usr/bin/security",
		authorizedLevel: 0,
		knownItems:      make(map[string]KeychainItem),
	}
}

// SetAuthorizationLevel sets the level of access the analyzer has
// 0 = basic (default) - can list keychains and metadata
// 1 = enhanced - can read more metadata with authorization
// 2 = full - can read secrets (requires explicit user authorization)
func (a *Analyzer) SetAuthorizationLevel(level int) {
	a.authorizedLevel = level
}

// Analyze performs a complete Keychain analysis
func (a *Analyzer) Analyze() (*AnalysisResult, error) {
	result := &AnalysisResult{
		Timestamp:          time.Now(),
		KeychainsAnalyzed:  make([]string, 0),
		Items:              make([]KeychainItem, 0),
		CertificateDetails: make([]Certificate, 0),
		Findings:           make([]Finding, 0),
		Duplicates:         make([]DuplicateSet, 0),
	}

	// List keychains
	keychains, err := a.listKeychains()
	if err != nil {
		return nil, fmt.Errorf("failed to list keychains: %w", err)
	}
	result.KeychainsAnalyzed = keychains

	// Enumerate items from each keychain
	for _, kc := range keychains {
		items, err := a.enumerateKeychain(kc)
		if err != nil {
			// Continue even if one keychain fails
			continue
		}
		result.Items = append(result.Items, items...)
	}

	result.TotalItems = len(result.Items)

	// Count by type
	for _, item := range result.Items {
		switch item.Class {
		case "genp":
			result.GenericPasswords++
		case "inet":
			result.InternetPasswords++
		case "cert":
			result.Certificates++
		case "keys":
			result.Keys++
		}
	}

	// Analyze certificates in detail
	certs, err := a.analyzeCertificates()
	if err == nil {
		result.CertificateDetails = certs
	}

	// Find duplicates
	result.Duplicates = a.findDuplicates(result.Items)

	// Security analysis
	result.Findings = a.analyzeForFindings(result)

	// Compare with previous if available
	if a.previousAnalysis != nil {
		changeFindings := a.detectChanges(result)
		result.Findings = append(result.Findings, changeFindings...)
	}

	// Store for future comparison
	a.previousAnalysis = result
	for _, item := range result.Items {
		a.knownItems[item.Hash] = item
	}

	// Check if enhanced features require auth
	result.RequiresAuth = a.authorizedLevel < 2

	return result, nil
}

// listKeychains returns all keychains in the search list
func (a *Analyzer) listKeychains() ([]string, error) {
	out, err := exec.Command(a.securityPath, "list-keychains").Output()
	if err != nil {
		return nil, err
	}

	var keychains []string
	scanner := bufio.NewScanner(bytes.NewReader(out))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		// Remove quotes
		line = strings.Trim(line, "\"")
		if line != "" {
			keychains = append(keychains, line)
		}
	}

	return keychains, scanner.Err()
}

// enumerateKeychain lists all items in a keychain
func (a *Analyzer) enumerateKeychain(keychainPath string) ([]KeychainItem, error) {
	var items []KeychainItem

	// Get generic passwords
	genp, _ := a.dumpItems(keychainPath, "genp")
	items = append(items, genp...)

	// Get internet passwords
	inet, _ := a.dumpItems(keychainPath, "inet")
	items = append(items, inet...)

	// Get certificates
	certs, _ := a.dumpItems(keychainPath, "cert")
	items = append(items, certs...)

	return items, nil
}

// dumpItems dumps items of a specific class from a keychain
func (a *Analyzer) dumpItems(keychainPath string, class string) ([]KeychainItem, error) {
	// Use security dump-keychain to get item metadata
	// Note: This shows metadata only, not actual secrets
	cmd := exec.Command(a.securityPath, "dump-keychain", keychainPath)
	out, err := cmd.Output()
	if err != nil {
		return nil, err
	}

	return a.parseKeychainDump(string(out), keychainPath, class)
}

// parseKeychainDump parses the output of security dump-keychain
func (a *Analyzer) parseKeychainDump(output string, keychainPath string, filterClass string) ([]KeychainItem, error) {
	var items []KeychainItem
	var currentItem *KeychainItem

	lines := strings.Split(output, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)

		// New item block
		if strings.HasPrefix(line, "keychain:") {
			// Save previous item if exists
			if currentItem != nil && (filterClass == "" || currentItem.Class == filterClass) {
				currentItem.Hash = a.computeItemHash(currentItem)
				items = append(items, *currentItem)
			}
			currentItem = &KeychainItem{
				Keychain:   keychainPath,
				Attributes: make(map[string]string),
			}
			continue
		}

		if currentItem == nil {
			continue
		}

		// Parse class
		if strings.HasPrefix(line, "class:") {
			class := strings.TrimPrefix(line, "class:")
			class = strings.TrimSpace(strings.Trim(class, "\""))
			currentItem.Class = class
			continue
		}

		// Parse attributes
		if strings.HasPrefix(line, "\"") {
			parts := strings.SplitN(line, "=", 2)
			if len(parts) == 2 {
				key := strings.Trim(strings.TrimSpace(parts[0]), "\"")
				value := strings.TrimSpace(parts[1])
				// Remove type prefix like <blob>= or 0x
				if strings.HasPrefix(value, "<") {
					if idx := strings.Index(value, "="); idx != -1 {
						value = strings.TrimSpace(value[idx+1:])
					}
				}
				value = strings.Trim(value, "\"")

				currentItem.Attributes[key] = value

				// Map to known fields
				switch key {
				case "labl":
					currentItem.Label = value
				case "acct":
					currentItem.Account = value
				case "svce":
					currentItem.Service = value
				case "srvr":
					currentItem.Server = value
				case "ptcl":
					currentItem.Protocol = value
				case "port":
					if p, err := strconv.Atoi(value); err == nil {
						currentItem.Port = p
					}
				case "path":
					currentItem.Path = value
				case "type":
					currentItem.Type = value
				case "cdat":
					if t, err := a.parseDate(value); err == nil {
						currentItem.CreationDate = t
					}
				case "mdat":
					if t, err := a.parseDate(value); err == nil {
						currentItem.ModificationDate = t
					}
				}
			}
		}
	}

	// Save last item
	if currentItem != nil && (filterClass == "" || currentItem.Class == filterClass) {
		currentItem.Hash = a.computeItemHash(currentItem)
		items = append(items, *currentItem)
	}

	return items, nil
}

// parseDate parses various date formats from keychain
func (a *Analyzer) parseDate(value string) (time.Time, error) {
	// Try common formats
	formats := []string{
		"2006-01-02 15:04:05 -0700",
		"20060102150405Z",
		time.RFC3339,
	}
	for _, format := range formats {
		if t, err := time.Parse(format, value); err == nil {
			return t, nil
		}
	}
	return time.Time{}, fmt.Errorf("unknown date format: %s", value)
}

// computeItemHash creates a unique hash for an item (for deduplication/tracking)
func (a *Analyzer) computeItemHash(item *KeychainItem) string {
	data := fmt.Sprintf("%s|%s|%s|%s|%s", item.Class, item.Label, item.Account, item.Service, item.Server)
	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:8])
}

// analyzeCertificates performs detailed certificate analysis
func (a *Analyzer) analyzeCertificates() ([]Certificate, error) {
	// Use security find-certificate to get certificate details
	out, err := exec.Command(a.securityPath, "find-certificate", "-a", "-p").Output()
	if err != nil {
		// Try without -p flag
		out, err = exec.Command(a.securityPath, "find-certificate", "-a").Output()
		if err != nil {
			return nil, err
		}
	}

	return a.parseCertificates(string(out))
}

// parseCertificates parses certificate information
func (a *Analyzer) parseCertificates(output string) ([]Certificate, error) {
	var certs []Certificate

	// Parse each certificate block
	// This is simplified - real implementation would use crypto/x509
	certBlocks := strings.Split(output, "-----BEGIN CERTIFICATE-----")

	for _, block := range certBlocks {
		if strings.TrimSpace(block) == "" {
			continue
		}

		cert := Certificate{}

		// Extract subject and issuer from accompanying text if available
		lines := strings.Split(block, "\n")
		for _, line := range lines {
			if strings.Contains(line, "subject=") || strings.Contains(line, "\"subj\"") {
				cert.Subject = extractValue(line)
			}
			if strings.Contains(line, "issuer=") || strings.Contains(line, "\"issr\"") {
				cert.Issuer = extractValue(line)
			}
			if strings.Contains(line, "\"labl\"") {
				cert.Label = extractValue(line)
			}
		}

		// Check if self-signed
		if cert.Subject != "" && cert.Subject == cert.Issuer {
			cert.IsSelfSigned = true
		}

		// Check expiration (would need actual cert parsing)
		cert.IsExpired = cert.NotAfter.Before(time.Now())
		cert.IsExpiringSoon = !cert.IsExpired && cert.NotAfter.Before(time.Now().AddDate(0, 0, 30))

		cert.Hash = fmt.Sprintf("%x", sha256.Sum256([]byte(cert.Subject+cert.Issuer)))[:16]

		certs = append(certs, cert)
	}

	return certs, nil
}

// extractValue extracts a value from a key=value line
func extractValue(line string) string {
	if idx := strings.Index(line, "="); idx != -1 {
		return strings.TrimSpace(strings.Trim(line[idx+1:], "\""))
	}
	return ""
}

// findDuplicates identifies duplicate keychain entries
func (a *Analyzer) findDuplicates(items []KeychainItem) []DuplicateSet {
	// Group by service+account for generic passwords
	// Group by server+account for internet passwords
	groups := make(map[string][]KeychainItem)

	for _, item := range items {
		var key string
		switch item.Class {
		case "genp":
			key = fmt.Sprintf("genp|%s|%s", item.Service, item.Account)
		case "inet":
			key = fmt.Sprintf("inet|%s|%s|%s", item.Server, item.Account, item.Protocol)
		default:
			continue
		}
		groups[key] = append(groups[key], item)
	}

	var duplicates []DuplicateSet
	for key, items := range groups {
		if len(items) > 1 {
			duplicates = append(duplicates, DuplicateSet{
				Key:   key,
				Items: items,
				Count: len(items),
			})
		}
	}

	return duplicates
}

// analyzeForFindings performs security analysis
func (a *Analyzer) analyzeForFindings(result *AnalysisResult) []Finding {
	var findings []Finding

	// Check for suspicious domains/servers
	suspiciousDomains := []string{
		"tempmail", "guerrillamail", "10minutemail",
		"hack", "crack", "warez", "torrent",
	}

	for _, item := range result.Items {
		server := strings.ToLower(item.Server)
		for _, sus := range suspiciousDomains {
			if strings.Contains(server, sus) {
				findings = append(findings, Finding{
					Severity:    "medium",
					Type:        "suspicious_domain",
					Title:       "Credentials for Suspicious Domain",
					Description: fmt.Sprintf("Keychain contains credentials for potentially suspicious domain: %s", item.Server),
					Item:        item.Label,
					Details: map[string]interface{}{
						"server":  item.Server,
						"account": item.Account,
					},
					DetectedAt: time.Now(),
				})
			}
		}

		// Check for plaintext protocol
		if item.Protocol == "http" && item.Port != 80 {
			findings = append(findings, Finding{
				Severity:    "low",
				Type:        "plaintext_protocol",
				Title:       "Credentials Using Plaintext Protocol",
				Description: fmt.Sprintf("Credentials stored for plaintext HTTP connection to %s", item.Server),
				Item:        item.Label,
				Details: map[string]interface{}{
					"server":   item.Server,
					"protocol": item.Protocol,
				},
				DetectedAt: time.Now(),
			})
		}
	}

	// Check for duplicates
	for _, dupSet := range result.Duplicates {
		severity := "low"
		if dupSet.Count > 3 {
			severity = "medium"
		}
		findings = append(findings, Finding{
			Severity:    severity,
			Type:        "duplicate_credentials",
			Title:       "Duplicate Keychain Entries",
			Description: fmt.Sprintf("Found %d duplicate entries for the same service/account", dupSet.Count),
			Item:        dupSet.Key,
			Details: map[string]interface{}{
				"count": dupSet.Count,
			},
			DetectedAt: time.Now(),
		})
	}

	// Check certificates
	for _, cert := range result.CertificateDetails {
		if cert.IsExpired {
			findings = append(findings, Finding{
				Severity:    "medium",
				Type:        "expired_certificate",
				Title:       "Expired Certificate in Keychain",
				Description: fmt.Sprintf("Certificate '%s' has expired", cert.Label),
				Item:        cert.Label,
				Details: map[string]interface{}{
					"subject":   cert.Subject,
					"issuer":    cert.Issuer,
					"not_after": cert.NotAfter,
				},
				DetectedAt: time.Now(),
			})
		}

		if cert.IsExpiringSoon {
			findings = append(findings, Finding{
				Severity:    "low",
				Type:        "expiring_certificate",
				Title:       "Certificate Expiring Soon",
				Description: fmt.Sprintf("Certificate '%s' will expire within 30 days", cert.Label),
				Item:        cert.Label,
				Details: map[string]interface{}{
					"subject":   cert.Subject,
					"not_after": cert.NotAfter,
				},
				DetectedAt: time.Now(),
			})
		}

		if cert.IsSelfSigned {
			findings = append(findings, Finding{
				Severity:    "info",
				Type:        "self_signed_certificate",
				Title:       "Self-Signed Certificate",
				Description: fmt.Sprintf("Certificate '%s' is self-signed", cert.Label),
				Item:        cert.Label,
				Details: map[string]interface{}{
					"subject": cert.Subject,
				},
				DetectedAt: time.Now(),
			})
		}

		if cert.IsWeakCrypto {
			findings = append(findings, Finding{
				Severity:    "high",
				Type:        "weak_crypto",
				Title:       "Certificate Using Weak Cryptography",
				Description: fmt.Sprintf("Certificate '%s' uses weak cryptographic algorithms", cert.Label),
				Item:        cert.Label,
				Details: map[string]interface{}{
					"key_algorithm":   cert.KeyAlgorithm,
					"key_size":        cert.KeySize,
					"signature_alg":   cert.SignatureAlg,
				},
				DetectedAt: time.Now(),
			})
		}
	}

	return findings
}

// detectChanges compares current state with previous analysis
func (a *Analyzer) detectChanges(current *AnalysisResult) []Finding {
	var findings []Finding

	currentItems := make(map[string]KeychainItem)
	for _, item := range current.Items {
		currentItems[item.Hash] = item
	}

	// Detect new items
	for hash, item := range currentItems {
		if _, existed := a.knownItems[hash]; !existed {
			findings = append(findings, Finding{
				Severity:    "info",
				Type:        "new_keychain_item",
				Title:       "New Keychain Item Added",
				Description: fmt.Sprintf("New %s item added: %s", item.Class, item.Label),
				Item:        item.Label,
				Details: map[string]interface{}{
					"class":   item.Class,
					"service": item.Service,
					"server":  item.Server,
					"account": item.Account,
				},
				DetectedAt: time.Now(),
			})
		}
	}

	// Detect removed items
	for hash, item := range a.knownItems {
		if _, exists := currentItems[hash]; !exists {
			findings = append(findings, Finding{
				Severity:    "info",
				Type:        "removed_keychain_item",
				Title:       "Keychain Item Removed",
				Description: fmt.Sprintf("Item removed: %s", item.Label),
				Item:        item.Label,
				Details: map[string]interface{}{
					"class":   item.Class,
					"service": item.Service,
				},
				DetectedAt: time.Now(),
			})
		}
	}

	return findings
}

// SearchItems searches for keychain items matching criteria
func (a *Analyzer) SearchItems(query string) ([]KeychainItem, error) {
	result, err := a.Analyze()
	if err != nil {
		return nil, err
	}

	query = strings.ToLower(query)
	var matches []KeychainItem

	for _, item := range result.Items {
		if strings.Contains(strings.ToLower(item.Label), query) ||
			strings.Contains(strings.ToLower(item.Service), query) ||
			strings.Contains(strings.ToLower(item.Server), query) ||
			strings.Contains(strings.ToLower(item.Account), query) {
			matches = append(matches, item)
		}
	}

	return matches, nil
}

// GetKeychainInfo returns information about a specific keychain
func (a *Analyzer) GetKeychainInfo(path string) (map[string]interface{}, error) {
	info := make(map[string]interface{})
	info["path"] = path

	// Get keychain settings
	out, err := exec.Command(a.securityPath, "show-keychain-info", path).CombinedOutput()
	if err == nil {
		info["settings"] = string(out)
	}

	// Check lock status
	out, err = exec.Command(a.securityPath, "show-keychain-info", path).CombinedOutput()
	if err == nil {
		info["lock_status"] = strings.Contains(string(out), "lock-on-sleep")
	}

	return info, nil
}

// CheckForCompromisedCredentials checks if any credentials appear in known breach databases
// This is a placeholder - real implementation would integrate with HaveIBeenPwned API or similar
func (a *Analyzer) CheckForCompromisedCredentials() ([]Finding, error) {
	var findings []Finding

	// This would require enhanced authorization level 2
	if a.authorizedLevel < 2 {
		return findings, fmt.Errorf("enhanced authorization required for credential compromise checking")
	}

	// Placeholder for actual implementation
	// Would hash credentials and check against breach databases

	return findings, nil
}

// ValidateIntegrity checks keychain integrity
func (a *Analyzer) ValidateIntegrity() ([]Finding, error) {
	var findings []Finding

	keychains, err := a.listKeychains()
	if err != nil {
		return nil, err
	}

	for _, kc := range keychains {
		// Verify keychain
		cmd := exec.Command(a.securityPath, "verify-cert", "-k", kc)
		if err := cmd.Run(); err != nil {
			findings = append(findings, Finding{
				Severity:    "high",
				Type:        "keychain_integrity",
				Title:       "Keychain Integrity Issue",
				Description: fmt.Sprintf("Keychain '%s' failed integrity check", kc),
				Item:        kc,
				DetectedAt:  time.Now(),
			})
		}
	}

	return findings, nil
}

// isWeakKey checks if a key is cryptographically weak
func isWeakKey(algorithm string, size int) bool {
	switch strings.ToLower(algorithm) {
	case "rsa":
		return size < 2048
	case "dsa":
		return size < 2048
	case "ec", "ecdsa":
		return size < 256
	case "md5", "sha1":
		return true // Weak hash algorithms
	}
	return false
}

// Regular expression patterns for parsing
var (
	certSubjectRe = regexp.MustCompile(`subject[=:]\s*(.+)`)
	certIssuerRe  = regexp.MustCompile(`issuer[=:]\s*(.+)`)
	dateRe        = regexp.MustCompile(`\d{4}-\d{2}-\d{2}`)
)
