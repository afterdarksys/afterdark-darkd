// Package packages parses read-only package-manager assessment output.
package packages

import (
	"fmt"
	"github.com/afterdarksys/afterdark-darkd/internal/platform"
	"strings"
)

func Installed(text string) ([]platform.Patch, error) {
	var out []platform.Patch
	for _, line := range strings.Split(text, "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		f := strings.Split(line, "|||")
		if len(f) != 2 {
			return nil, fmt.Errorf("malformed installed package record")
		}
		out = append(out, platform.Patch{ID: f[0] + "@" + f[1], Name: f[0], Description: f[1]})
	}
	return out, nil
}
func APT(text string) ([]platform.Patch, error) {
	var out []platform.Patch
	for _, line := range strings.Split(text, "\n") {
		if !strings.HasPrefix(line, "Inst ") {
			continue
		}
		fields := strings.Fields(line)
		open := strings.Index(line, "(")
		if len(fields) < 3 || open < 0 {
			return nil, fmt.Errorf("malformed apt update record")
		}
		version := strings.Fields(line[open+1:])
		if len(version) == 0 {
			return nil, fmt.Errorf("missing apt candidate version")
		}
		out = append(out, platform.Patch{ID: fields[1] + "@" + strings.TrimSuffix(version[0], ")"), Name: fields[1], Description: line, Severity: platform.SeverityUnknown})
	}
	return out, nil
}
func DNF(text string) ([]platform.Patch, error) {
	var out []platform.Patch
	for _, line := range strings.Split(text, "\n") {
		f := strings.Fields(line)
		if len(f) != 3 || !strings.Contains(f[0], ".") {
			continue
		}
		out = append(out, platform.Patch{ID: f[0] + "@" + f[1], Name: f[0], Description: line, Severity: platform.SeverityUnknown})
	}
	return out, nil
}
