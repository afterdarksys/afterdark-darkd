package investigation

import (
	"os"
	"testing"
)

func TestPlatformRulePackPositiveAndMissingEvidence(t *testing.T) {
	f, err := os.Open("../../configs/investigation-platform-rules.json")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	rules, err := LoadRules(f)
	if err != nil {
		t.Fatal(err)
	}
	fixtures := []struct {
		id, kind string
		fields   map[string]string
	}{
		{"server.wildcard-admin-listener", "network.observed", map[string]string{"network.local_address": "0.0.0.0", "network.local_port": "22", "network.state": "LISTEN"}},
		{"server.metadata-access", "network.observed", map[string]string{"network.remote_address": "169.254.169.254"}},
		{"linux.user-writable-process", "process.observed", map[string]string{"process.executable": "/tmp/tool"}},
		{"macos.downloaded-process", "process.observed", map[string]string{"process.executable": "/Users/test/Downloads/tool"}},
		{"windows.user-writable-process", "process.observed", map[string]string{"process.executable": `C:\Users\test\Downloads\tool.exe`}},
		{"windows.encoded-powershell", "process.observed", map[string]string{"process.name": "powershell.exe", "process.command_line": "powershell.exe -EncodedCommand ABCD"}},
	}
	for _, f := range fixtures {
		t.Run(f.id, func(t *testing.T) {
			matches := rules.Evaluate(Event{ID: "fixture", Kind: f.kind, Fields: f.fields})
			found := false
			for _, m := range matches {
				if m.RuleID == f.id {
					found = true
				}
			}
			if !found {
				t.Fatal("expected rule missing", matches)
			}
			for key := range f.fields {
				negative := map[string]string{}
				for k, v := range f.fields {
					if k != key {
						negative[k] = v
					}
				}
				for _, m := range rules.Evaluate(Event{Kind: f.kind, Fields: negative}) {
					if m.RuleID == f.id {
						t.Fatal("missing evidence matched", key)
					}
				}
			}
		})
	}
}
