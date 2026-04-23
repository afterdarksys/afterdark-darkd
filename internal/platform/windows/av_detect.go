//go:build windows

package windows

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

// DetectSecurityAgents scans for known AV/EDR/MDM agents on Windows by checking
// well-known installation paths and correlating with running processes via tasklist.
func DetectSecurityAgents() []DetectedSecurityAgent {
	var found []DetectedSecurityAgent

	agents := []struct {
		name      string
		agentType string
		paths     []string
		process   string
	}{
		{"CrowdStrike Falcon", "edr", []string{`C:\Program Files\CrowdStrike`, `C:\Windows\System32\drivers\CrowdStrike`}, "CSFalconService.exe"},
		{"SentinelOne", "edr", []string{`C:\Program Files\SentinelOne`}, "SentinelAgent.exe"},
		{"Carbon Black", "edr", []string{`C:\Program Files\Confer`, `C:\Program Files\VMware\Carbon Black Cloud`}, "RepMgr.exe"},
		{"Microsoft Defender", "av", []string{`C:\ProgramData\Microsoft\Windows Defender`}, "MsMpEng.exe"},
		{"Cylance", "av", []string{`C:\Program Files\Cylance\CylancePROTECT`}, "CylanceSvc.exe"},
		{"Sophos", "av", []string{`C:\Program Files\Sophos`}, "SophosScanD.exe"},
		{"ESET", "av", []string{`C:\Program Files\ESET`}, "ekrn.exe"},
		{"Trend Micro", "av", []string{`C:\Program Files\Trend Micro`}, "tmbmsrv.exe"},
		{"Qualys", "edr", []string{`C:\Program Files\Qualys\QualysAgent`}, "QualysAgent.exe"},
		{"Tanium", "edr", []string{`C:\Program Files\Tanium\Tanium Client`}, "TaniumClient.exe"},
	}

	// Snapshot running processes once via tasklist
	taskOut, _ := exec.Command("tasklist", "/NH").Output()
	taskStr := strings.ToLower(string(taskOut))

	for _, a := range agents {
		for _, path := range a.paths {
			if _, err := os.Stat(path); err == nil {
				found = append(found, DetectedSecurityAgent{
					Name:    a.name,
					Type:    a.agentType,
					Running: strings.Contains(taskStr, strings.ToLower(a.process)),
				})
				break
			}
		}
	}
	return found
}
