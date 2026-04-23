//go:build darwin

package macos

import (
	"os"
	"os/exec"
	"strings"
)

// DetectedSecurityAgent represents a detected AV/EDR/security tool
type DetectedSecurityAgent struct {
	Name    string
	Type    string // "av", "edr", "mdm", "firewall"
	Running bool
}

// DetectSecurityAgents scans for known AV/EDR/MDM agents on macOS by checking
// well-known installation paths and correlating with running processes.
func DetectSecurityAgents() []DetectedSecurityAgent {
	var found []DetectedSecurityAgent

	agents := []struct {
		name      string
		agentType string
		paths     []string
		process   string
	}{
		{"CrowdStrike Falcon", "edr", []string{"/Library/CS/falcond"}, "falcond"},
		{"SentinelOne", "edr", []string{"/Library/Sentinel/sentinel-agent.bundle"}, "SentinelAgent"},
		{"Carbon Black", "edr", []string{"/Applications/VMware Carbon Black Cloud"}, "cbdaemon"},
		{"Jamf Protect", "edr", []string{"/Library/Application Support/JamfProtect"}, "JamfProtect"},
		{"Malwarebytes", "av", []string{"/Applications/Malwarebytes.app"}, "Malwarebytes"},
		{"Sophos", "av", []string{"/Library/Sophos Anti-Virus"}, "SophosScanD"},
		{"Cisco Secure", "edr", []string{"/opt/cisco/amp"}, "ampdaemon"},
		{"Kandji", "mdm", []string{"/Library/Kandji"}, "kandji-daemon"},
		{"Jamf Pro", "mdm", []string{"/Library/Application Support/JAMF"}, "jamf"},
		{"Microsoft Defender", "av", []string{"/Applications/Microsoft Defender.app"}, "wdavdaemon"},
	}

	// Snapshot of running processes — run once to avoid N execs
	psOut, _ := exec.Command("ps", "aux").Output()
	psStr := string(psOut)

	for _, a := range agents {
		for _, path := range a.paths {
			if _, err := os.Stat(path); err == nil {
				found = append(found, DetectedSecurityAgent{
					Name:    a.name,
					Type:    a.agentType,
					Running: strings.Contains(psStr, a.process),
				})
				break
			}
		}
	}
	return found
}
