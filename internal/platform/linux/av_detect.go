//go:build linux

package linux

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

// DetectSecurityAgents scans for known AV/EDR/MDM agents on Linux by checking
// well-known installation paths and correlating with running processes.
func DetectSecurityAgents() []DetectedSecurityAgent {
	var found []DetectedSecurityAgent

	agents := []struct {
		name      string
		agentType string
		paths     []string
		process   string
	}{
		{"CrowdStrike Falcon", "edr", []string{"/opt/CrowdStrike/falcond", "/opt/CrowdStrike"}, "falcond"},
		{"SentinelOne", "edr", []string{"/opt/sentinelone", "/usr/local/bin/sentinelctl"}, "sentineld"},
		{"Carbon Black", "edr", []string{"/opt/carbonblack", "/usr/share/cb"}, "cbdaemon"},
		{"Cylance", "av", []string{"/opt/cylance"}, "cylancesvc"},
		{"Sophos", "av", []string{"/opt/sophos-av", "/usr/lib/sophos"}, "savd"},
		{"ESET", "av", []string{"/opt/eset"}, "esets_daemon"},
		{"Trend Micro", "av", []string{"/opt/ds_agent", "/etc/opt/ds_agent"}, "ds_agent"},
		{"Microsoft Defender", "av", []string{"/opt/microsoft/mdatp"}, "mdatp"},
		{"Qualys", "edr", []string{"/usr/local/qualys/cloud-agent"}, "qualys-cloud-agent"},
		{"Osquery", "edr", []string{"/usr/bin/osqueryd", "/var/osquery"}, "osqueryd"},
	}

	// Snapshot of running processes once
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
