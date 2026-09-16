package detonation

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestShortFilesAndMalformedExecutables(t *testing.T) {
	for _, data := range []string{"", "a", "ab", "abc", "MZbroken", "\x7fELFbroken"} {
		path := filepath.Join(t.TempDir(), "sample")
		os.WriteFile(path, []byte(data), 0600)
		_, err := NewFileAnalyzer("", false).PerformStaticAnalysis(path)
		if (data == "MZbroken" || data == "\x7fELFbroken") && err == nil {
			t.Fatal("malformed executable accepted")
		}
	}
}

func TestActualYARAMatching(t *testing.T) {
	if _, err := exec.LookPath("yara"); err != nil {
		t.Skip("yara executable required")
	}
	dir := t.TempDir()
	rules := filepath.Join(dir, "rules")
	os.Mkdir(rules, 0700)
	os.WriteFile(filepath.Join(rules, "test.yar"), []byte(`rule evidence { strings: $a = "distinctive-test-marker" condition: $a }`), 0600)
	path := filepath.Join(dir, "sample")
	os.WriteFile(path, []byte("distinctive-test-marker"), 0600)
	result, err := NewFileAnalyzer(rules, true).PerformStaticAnalysis(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.YaraMatches) != 1 || result.YaraMatches[0] != "evidence" {
		t.Fatalf("matches: %v", result.YaraMatches)
	}
	os.WriteFile(filepath.Join(rules, "bad.yar"), []byte("invalid rule"), 0600)
	if _, err := NewFileAnalyzer(rules, true).PerformStaticAnalysis(path); err == nil {
		t.Fatal("invalid rule silently ignored")
	}
}
