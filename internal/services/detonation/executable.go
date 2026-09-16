package detonation

import (
	"context"
	"debug/elf"
	"debug/pe"
	"fmt"
	"github.com/afterdarksys/afterdark-darkd/internal/models"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

func (a *FileAnalyzer) executableMetadata(path string, analysis *models.StaticAnalysis) error {
	switch analysis.FileType {
	case "ELF":
		f, err := elf.Open(path)
		if err != nil {
			return fmt.Errorf("parse ELF: %w", err)
		}
		defer f.Close()
		for _, section := range f.Sections {
			entropy, err := a.calculateEntropy(io.LimitReader(section.Open(), 16<<20))
			if err != nil {
				return err
			}
			permissions := "r"
			if section.Flags&elf.SHF_WRITE != 0 {
				permissions += "w"
			}
			if section.Flags&elf.SHF_EXECINSTR != 0 {
				permissions += "x"
			}
			analysis.Sections = append(analysis.Sections, models.SectionInfo{Name: section.Name, VirtualSize: int64(section.Size), RawSize: int64(section.FileSize), Entropy: entropy, Permissions: permissions, IsSuspicious: strings.Contains(permissions, "wx")})
		}
		symbols, err := f.ImportedSymbols()
		if err != nil && err != elf.ErrNoSymbols {
			return err
		}
		imports := map[string][]string{}
		for _, symbol := range symbols {
			imports[symbol.Library] = append(imports[symbol.Library], symbol.Name)
		}
		for library, functions := range imports {
			analysis.Imports = append(analysis.Imports, models.ImportInfo{Library: library, Functions: functions})
		}
		dynamic, err := f.DynamicSymbols()
		if err != nil && err != elf.ErrNoSymbols {
			return err
		}
		for _, symbol := range dynamic {
			if symbol.Section != elf.SHN_UNDEF && elf.ST_BIND(symbol.Info) == elf.STB_GLOBAL {
				analysis.Exports = append(analysis.Exports, symbol.Name)
			}
		}
	case "PE/EXE":
		f, err := pe.Open(path)
		if err != nil {
			return fmt.Errorf("parse PE: %w", err)
		}
		defer f.Close()
		for _, section := range f.Sections {
			entropy, err := a.calculateEntropy(io.LimitReader(section.Open(), 16<<20))
			if err != nil {
				return err
			}
			permissions := ""
			if section.Characteristics&0x40000000 != 0 {
				permissions += "r"
			}
			if section.Characteristics&0x80000000 != 0 {
				permissions += "w"
			}
			if section.Characteristics&0x20000000 != 0 {
				permissions += "x"
			}
			analysis.Sections = append(analysis.Sections, models.SectionInfo{Name: section.Name, VirtualSize: int64(section.VirtualSize), RawSize: int64(section.Size), Entropy: entropy, Permissions: permissions, IsSuspicious: strings.Contains(permissions, "wx")})
		}
		symbols, err := f.ImportedSymbols()
		if err != nil {
			return err
		}
		imports := map[string][]string{}
		for _, symbol := range symbols {
			function, library, _ := strings.Cut(symbol, ":")
			imports[library] = append(imports[library], function)
		}
		for library, functions := range imports {
			analysis.Imports = append(analysis.Imports, models.ImportInfo{Library: library, Functions: functions})
		}
		// COFF externally visible symbols are available for unstripped objects.
		for _, symbol := range f.Symbols {
			if symbol.StorageClass == 2 && symbol.SectionNumber > 0 {
				analysis.Exports = append(analysis.Exports, symbol.Name)
			}
		}
	}
	sort.Slice(analysis.Imports, func(i, j int) bool { return analysis.Imports[i].Library < analysis.Imports[j].Library })
	sort.Strings(analysis.Exports)
	return nil
}

func (a *FileAnalyzer) matchYARA(path string) ([]string, error) {
	if !a.enableYara {
		return nil, nil
	}
	entries, err := os.ReadDir(a.yaraRulesDir)
	if err != nil {
		return nil, fmt.Errorf("read YARA rules: %w", err)
	}
	binary, err := exec.LookPath("yara")
	if err != nil {
		return nil, fmt.Errorf("YARA enabled but scanner unavailable: %w", err)
	}
	target, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	var matches []string
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	for _, entry := range entries {
		if entry.IsDir() || entry.Type()&os.ModeSymlink != 0 || (filepath.Ext(entry.Name()) != ".yar" && filepath.Ext(entry.Name()) != ".yara") {
			continue
		}
		rules, err := filepath.Abs(filepath.Join(a.yaraRulesDir, entry.Name()))
		if err != nil {
			return nil, err
		}
		cmd := exec.CommandContext(ctx, binary, "-w", "--timeout=10", rules, target)
		// One match per rule, bounded by the rule file size enforced by rule management.
		output, err := cmd.Output()
		if err != nil {
			return nil, fmt.Errorf("YARA scan %s failed: %w", entry.Name(), err)
		}
		for _, line := range strings.Split(string(output), "\n") {
			fields := strings.Fields(line)
			if len(fields) > 0 {
				matches = append(matches, fields[0])
			}
		}
	}
	sort.Strings(matches)
	return matches, nil
}
