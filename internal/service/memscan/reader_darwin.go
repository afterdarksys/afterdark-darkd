//go:build darwin

package memscan

import (
	"fmt"
	"github.com/afterdarksys/afterdark-darkd/internal/models"
	"github.com/shirou/gopsutil/v3/process"
	"go.uber.org/zap"
	"time"
)

// DarwinReader reads process memory on macOS
// Note: Full implementation requires Mach API access which needs special entitlements
type DarwinReader struct {
	logger *zap.Logger
}

// NewDarwinReader creates a new macOS memory reader
func NewDarwinReader(logger *zap.Logger) (*DarwinReader, error) {
	return &DarwinReader{logger: logger.Named("darwin-reader")}, nil
}

// ListProcesses returns list of running processes
func (r *DarwinReader) ListProcesses() ([]models.ScanProcessInfo, error) {
	pids, err := process.Pids()
	if err != nil {
		return nil, err
	}
	result := make([]models.ScanProcessInfo, 0, len(pids))
	for _, pid := range pids {
		info, err := r.GetProcessInfo(int(pid))
		if err == nil {
			result = append(result, *info)
		}
	}
	return result, nil
}

func (r *DarwinReader) GetProcessInfo(pid int) (*models.ScanProcessInfo, error) {
	if pid <= 0 {
		return nil, fmt.Errorf("invalid PID")
	}
	p, err := process.NewProcess(int32(pid))
	if err != nil {
		return nil, err
	}
	name, err := p.Name()
	if err != nil {
		return nil, err
	}
	path, _ := p.Exe()
	parent, _ := p.Ppid()
	username, _ := p.Username()
	created, _ := p.CreateTime()
	return &models.ScanProcessInfo{PID: pid, PPID: int(parent), Name: name, Path: path, Username: username, IsSystem: username == "root", StartTime: time.UnixMilli(created)}, nil
}

func (r *DarwinReader) GetMemoryRegions(pid int) ([]models.MemoryRegion, error) {
	return darwinRegions(pid)
}
func (r *DarwinReader) ReadMemory(pid int, address, size uint64) ([]byte, error) {
	return darwinRead(pid, address, size)
}

// IsLSASS returns false on macOS (Windows-only concept)
func (r *DarwinReader) IsLSASS(pid int) bool {
	return false
}
