//go:build darwin

package macos

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/afterdarksys/afterdark-darkd/internal/platform"
)

// Regular expressions for parsing softwareupdate output
var (
	// Matches: "* Label: macOS Sonoma 14.2.1-23C71"
	updateLabelRe = regexp.MustCompile(`^\s*\*\s*Label:\s*(.+)$`)

	// Matches: "Title: macOS Sonoma 14.2.1"
	updateTitleRe = regexp.MustCompile(`^\s*Title:\s*(.+)$`)

	// Matches: "Version: 14.2.1"
	updateVersionRe = regexp.MustCompile(`^\s*Version:\s*(.+)$`)

	// Matches: "Size: 1234K" or "Size: 1234M" or "Size: 1.2G"
	updateSizeRe = regexp.MustCompile(`^\s*Size:\s*([\d.]+)([KMG]?)`)

	// Matches: "Recommended: YES" or "Recommended: NO"
	updateRecommendedRe = regexp.MustCompile(`^\s*Recommended:\s*(YES|NO)`)

	// Matches: "Action: restart"
	updateActionRe = regexp.MustCompile(`^\s*Action:\s*(.+)$`)

	// History format: "Display Name           Version    Date                  "
	historyLineRe = regexp.MustCompile(`^(.+?)\s{2,}([\d.]+)\s{2,}(\d{2}/\d{2}/\d{4},\s*\d{2}:\d{2}:\d{2})`)

	// Security update patterns
	securityPatterns = []string{
		"security",
		"Security Update",
		"XProtect",
		"MRT",
		"Gatekeeper",
	}

	// Critical update patterns
	criticalPatterns = []string{
		"critical",
		"emergency",
		"urgent",
		"zero-day",
		"actively exploited",
	}
)

// ListAvailablePatches returns available macOS updates using softwareupdate
func (p *Platform) ListAvailablePatches(ctx context.Context) ([]platform.Patch, error) {
	// Run softwareupdate -l (list available updates)
	cmd := exec.CommandContext(ctx, "softwareupdate", "-l", "--all")
	output, err := cmd.Output()
	if err != nil {
		// Check if it's just "no updates available"
		if exitErr, ok := err.(*exec.ExitError); ok {
			stderr := string(exitErr.Stderr)
			if strings.Contains(stderr, "No new software available") {
				return []platform.Patch{}, nil
			}
		}
		return nil, fmt.Errorf("softwareupdate -l failed: %w", err)
	}

	return parseAvailableUpdates(output)
}

// parseAvailableUpdates parses the output of softwareupdate -l
func parseAvailableUpdates(output []byte) ([]platform.Patch, error) {
	var patches []platform.Patch
	scanner := bufio.NewScanner(bytes.NewReader(output))

	var currentPatch *platform.Patch

	for scanner.Scan() {
		line := scanner.Text()

		// Check for new update label
		if matches := updateLabelRe.FindStringSubmatch(line); len(matches) > 1 {
			// Save previous patch if exists
			if currentPatch != nil {
				patches = append(patches, *currentPatch)
			}

			// Start new patch
			label := strings.TrimSpace(matches[1])
			currentPatch = &platform.Patch{
				ID:         label,
				Name:       label,
				ReleasedAt: time.Now(), // Will be updated if we can find release date
				Category:   determineCategoryFromName(label),
				Severity:   determineSeverityFromName(label),
			}
			continue
		}

		// Skip if we don't have a current patch
		if currentPatch == nil {
			continue
		}

		// Parse title
		if matches := updateTitleRe.FindStringSubmatch(line); len(matches) > 1 {
			currentPatch.Name = strings.TrimSpace(matches[1])
			continue
		}

		// Parse version
		if matches := updateVersionRe.FindStringSubmatch(line); len(matches) > 1 {
			currentPatch.Description = fmt.Sprintf("Version %s", strings.TrimSpace(matches[1]))
			continue
		}

		// Parse size
		if matches := updateSizeRe.FindStringSubmatch(line); len(matches) > 1 {
			size := parseSize(matches[1], matches[2])
			currentPatch.Size = size
			continue
		}

		// Parse recommended
		if matches := updateRecommendedRe.FindStringSubmatch(line); len(matches) > 1 {
			if matches[1] == "YES" {
				// Recommended updates are at least important
				if currentPatch.Severity < platform.SeverityImportant {
					currentPatch.Severity = platform.SeverityImportant
				}
			}
			continue
		}

		// Parse action (restart means it's more important)
		if matches := updateActionRe.FindStringSubmatch(line); len(matches) > 1 {
			action := strings.TrimSpace(matches[1])
			if action == "restart" || action == "shut down" {
				// Updates requiring restart are typically kernel/system updates
				if currentPatch.Category == platform.CategoryUnknown {
					currentPatch.Category = platform.CategoryKernel
				}
			}
			continue
		}
	}

	// Don't forget the last patch
	if currentPatch != nil {
		patches = append(patches, *currentPatch)
	}

	return patches, scanner.Err()
}

// ListInstalledPatches returns installed macOS updates using softwareupdate --history
func (p *Platform) ListInstalledPatches(ctx context.Context) ([]platform.Patch, error) {
	// Try softwareupdate --history first (macOS 10.15+)
	patches, err := p.listPatchesFromHistory(ctx)
	if err == nil && len(patches) > 0 {
		return patches, nil
	}

	// Fall back to system_profiler
	return p.listPatchesFromSystemProfiler(ctx)
}

// listPatchesFromHistory uses softwareupdate --history
func (p *Platform) listPatchesFromHistory(ctx context.Context) ([]platform.Patch, error) {
	cmd := exec.CommandContext(ctx, "softwareupdate", "--history", "--all")
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("softwareupdate --history failed: %w", err)
	}

	return parseHistoryOutput(output)
}

// parseHistoryOutput parses softwareupdate --history output
func parseHistoryOutput(output []byte) ([]platform.Patch, error) {
	var patches []platform.Patch
	scanner := bufio.NewScanner(bytes.NewReader(output))

	// Skip header lines
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := scanner.Text()

		// Skip header (first 2 lines typically)
		if lineNum <= 2 {
			continue
		}

		// Skip separator lines
		if strings.HasPrefix(line, "-") || strings.TrimSpace(line) == "" {
			continue
		}

		// Parse line: "Display Name           Version    Date"
		if matches := historyLineRe.FindStringSubmatch(line); len(matches) > 3 {
			name := strings.TrimSpace(matches[1])
			version := strings.TrimSpace(matches[2])
			dateStr := strings.TrimSpace(matches[3])

			installedAt, _ := time.Parse("01/02/2006, 15:04:05", dateStr)

			patch := platform.Patch{
				ID:          fmt.Sprintf("%s-%s", name, version),
				Name:        name,
				Description: fmt.Sprintf("Version %s", version),
				InstalledAt: &installedAt,
				ReleasedAt:  installedAt, // Use install time as approximate release
				Category:    determineCategoryFromName(name),
				Severity:    determineSeverityFromName(name),
			}

			patches = append(patches, patch)
		}
	}

	return patches, scanner.Err()
}

// listPatchesFromSystemProfiler uses system_profiler as fallback
func (p *Platform) listPatchesFromSystemProfiler(ctx context.Context) ([]platform.Patch, error) {
	cmd := exec.CommandContext(ctx, "system_profiler", "SPInstallHistoryDataType", "-xml")
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("system_profiler failed: %w", err)
	}

	return parseSystemProfilerOutput(output)
}

// parseSystemProfilerOutput parses system_profiler XML output
// This is a simplified parser - in production you'd use proper plist parsing
func parseSystemProfilerOutput(output []byte) ([]platform.Patch, error) {
	var patches []platform.Patch

	// Look for install entries in the plist XML
	// Format: <key>_name</key><string>Update Name</string>
	//         <key>install_date</key><date>2024-01-15T10:30:00Z</date>
	//         <key>install_version</key><string>1.0</string>

	lines := strings.Split(string(output), "\n")
	var currentName, currentVersion string
	var currentDate time.Time

	for i, line := range lines {
		line = strings.TrimSpace(line)

		if strings.Contains(line, "<key>_name</key>") && i+1 < len(lines) {
			currentName = extractStringValue(lines[i+1])
		}

		if strings.Contains(line, "<key>install_version</key>") && i+1 < len(lines) {
			currentVersion = extractStringValue(lines[i+1])
		}

		if strings.Contains(line, "<key>install_date</key>") && i+1 < len(lines) {
			dateStr := extractDateValue(lines[i+1])
			currentDate, _ = time.Parse(time.RFC3339, dateStr)
		}

		// When we hit a dict boundary, save if we have data
		if strings.Contains(line, "</dict>") && currentName != "" {
			patch := platform.Patch{
				ID:          fmt.Sprintf("%s-%s", currentName, currentVersion),
				Name:        currentName,
				Description: fmt.Sprintf("Version %s", currentVersion),
				InstalledAt: &currentDate,
				ReleasedAt:  currentDate,
				Category:    determineCategoryFromName(currentName),
				Severity:    determineSeverityFromName(currentName),
			}
			patches = append(patches, patch)

			currentName = ""
			currentVersion = ""
			currentDate = time.Time{}
		}
	}

	return patches, nil
}

// extractStringValue extracts value from <string>value</string>
func extractStringValue(line string) string {
	line = strings.TrimSpace(line)
	line = strings.TrimPrefix(line, "<string>")
	line = strings.TrimSuffix(line, "</string>")
	return line
}

// extractDateValue extracts value from <date>value</date>
func extractDateValue(line string) string {
	line = strings.TrimSpace(line)
	line = strings.TrimPrefix(line, "<date>")
	line = strings.TrimSuffix(line, "</date>")
	return line
}

// determineCategoryFromName determines the patch category based on its name
func determineCategoryFromName(name string) platform.PatchCategory {
	nameLower := strings.ToLower(name)

	// Kernel/OS updates
	if strings.Contains(nameLower, "macos") ||
		strings.Contains(nameLower, "os x") ||
		strings.Contains(nameLower, "darwin") {
		return platform.CategoryKernel
	}

	// Security updates
	for _, pattern := range securityPatterns {
		if strings.Contains(nameLower, strings.ToLower(pattern)) {
			return platform.CategorySecurity
		}
	}

	// Network-related
	if strings.Contains(nameLower, "network") ||
		strings.Contains(nameLower, "wifi") ||
		strings.Contains(nameLower, "bluetooth") ||
		strings.Contains(nameLower, "airport") {
		return platform.CategoryNetwork
	}

	// Default to software
	return platform.CategorySoftware
}

// determineSeverityFromName determines the patch severity based on its name and content
func determineSeverityFromName(name string) platform.PatchSeverity {
	nameLower := strings.ToLower(name)

	// Check for critical indicators
	for _, pattern := range criticalPatterns {
		if strings.Contains(nameLower, strings.ToLower(pattern)) {
			return platform.SeverityCritical
		}
	}

	// Security updates are at least Important
	for _, pattern := range securityPatterns {
		if strings.Contains(nameLower, strings.ToLower(pattern)) {
			return platform.SeverityImportant
		}
	}

	// macOS updates are typically important
	if strings.Contains(nameLower, "macos") || strings.Contains(nameLower, "os x") {
		return platform.SeverityImportant
	}

	// Default to moderate
	return platform.SeverityModerate
}

// parseSize converts size string to bytes
func parseSize(sizeStr, unit string) int64 {
	size, err := strconv.ParseFloat(sizeStr, 64)
	if err != nil {
		return 0
	}

	switch strings.ToUpper(unit) {
	case "K":
		return int64(size * 1024)
	case "M":
		return int64(size * 1024 * 1024)
	case "G":
		return int64(size * 1024 * 1024 * 1024)
	default:
		return int64(size)
	}
}

// InstallPatch installs a specific macOS update
func (p *Platform) InstallPatch(ctx context.Context, patchID string) error {
	// Use softwareupdate -i to install
	// Note: This requires root privileges
	cmd := exec.CommandContext(ctx, "softwareupdate", "-i", patchID)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to install patch %s: %w\nOutput: %s", patchID, err, string(output))
	}

	return nil
}

// ListInstalledApplications returns installed macOS applications
func (p *Platform) ListInstalledApplications(ctx context.Context) ([]platform.Application, error) {
	cmd := exec.CommandContext(ctx, "system_profiler", "SPApplicationsDataType", "-xml")
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("system_profiler failed: %w", err)
	}

	return parseApplicationsOutput(output)
}

// parseApplicationsOutput parses system_profiler SPApplicationsDataType output
func parseApplicationsOutput(output []byte) ([]platform.Application, error) {
	var apps []platform.Application

	lines := strings.Split(string(output), "\n")
	var currentName, currentVersion, currentPath string
	var currentDate time.Time

	for i, line := range lines {
		line = strings.TrimSpace(line)

		if strings.Contains(line, "<key>_name</key>") && i+1 < len(lines) {
			currentName = extractStringValue(lines[i+1])
		}

		if strings.Contains(line, "<key>version</key>") && i+1 < len(lines) {
			currentVersion = extractStringValue(lines[i+1])
		}

		if strings.Contains(line, "<key>path</key>") && i+1 < len(lines) {
			currentPath = extractStringValue(lines[i+1])
		}

		if strings.Contains(line, "<key>lastModified</key>") && i+1 < len(lines) {
			dateStr := extractDateValue(lines[i+1])
			currentDate, _ = time.Parse(time.RFC3339, dateStr)
		}

		// When we hit a dict boundary, save if we have data
		if strings.Contains(line, "</dict>") && currentName != "" {
			app := platform.Application{
				Name:        currentName,
				Version:     currentVersion,
				InstallPath: currentPath,
				InstallDate: currentDate,
				Vendor:      extractVendorFromPath(currentPath),
			}
			apps = append(apps, app)

			currentName = ""
			currentVersion = ""
			currentPath = ""
			currentDate = time.Time{}
		}
	}

	return apps, nil
}

// extractVendorFromPath tries to determine vendor from application path
func extractVendorFromPath(path string) string {
	pathLower := strings.ToLower(path)

	// Common vendor paths
	if strings.Contains(pathLower, "/apple/") || strings.HasPrefix(pathLower, "/system/") {
		return "Apple Inc."
	}
	if strings.Contains(pathLower, "microsoft") {
		return "Microsoft Corporation"
	}
	if strings.Contains(pathLower, "google") {
		return "Google LLC"
	}
	if strings.Contains(pathLower, "adobe") {
		return "Adobe Inc."
	}

	return "Unknown"
}
