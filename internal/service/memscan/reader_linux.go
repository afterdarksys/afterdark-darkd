//go:build linux

package memscan

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/afterdarksys/afterdark-darkd/internal/models"
	"go.uber.org/zap"
)

// LinuxReader reads process memory on Linux
type LinuxReader struct {
	logger *zap.Logger
}

// NewLinuxReader creates a new Linux memory reader
func NewLinuxReader(logger *zap.Logger) (*LinuxReader, error) {
	return &LinuxReader{logger: logger.Named("linux-reader")}, nil
}

// ListProcesses returns list of running processes
func (r *LinuxReader) ListProcesses() ([]models.ScanProcessInfo, error) {
	var processes []models.ScanProcessInfo

	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil, err
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		pid, err := strconv.Atoi(entry.Name())
		if err != nil {
			continue // Not a PID directory
		}

		proc, err := r.GetProcessInfo(pid)
		if err != nil {
			continue
		}

		if proc != nil {
			processes = append(processes, *proc)
		}
	}

	return processes, nil
}

// GetProcessInfo reads process information from /proc
func (r *LinuxReader) GetProcessInfo(pid int) (*models.ScanProcessInfo, error) {
	proc := &models.ScanProcessInfo{PID: pid}

	// Read /proc/[pid]/comm for process name
	commPath := filepath.Join("/proc", strconv.Itoa(pid), "comm")
	if data, err := os.ReadFile(commPath); err == nil {
		proc.Name = strings.TrimSpace(string(data))
	}

	// Read /proc/[pid]/exe for executable path
	exePath := filepath.Join("/proc", strconv.Itoa(pid), "exe")
	if link, err := os.Readlink(exePath); err == nil {
		proc.Path = link
	}

	// Read /proc/[pid]/cmdline
	cmdlinePath := filepath.Join("/proc", strconv.Itoa(pid), "cmdline")
	if data, err := os.ReadFile(cmdlinePath); err == nil {
		proc.CommandLine = strings.ReplaceAll(string(data), "\x00", " ")
	}

	// Read /proc/[pid]/status for additional info
	statusPath := filepath.Join("/proc", strconv.Itoa(pid), "status")
	if file, err := os.Open(statusPath); err == nil {
		defer file.Close()
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			line := scanner.Text()
			if strings.HasPrefix(line, "PPid:") {
				parts := strings.Fields(line)
				if len(parts) >= 2 {
					proc.PPID, _ = strconv.Atoi(parts[1])
				}
			} else if strings.HasPrefix(line, "Uid:") {
				parts := strings.Fields(line)
				if len(parts) >= 2 {
					uid, _ := strconv.Atoi(parts[1])
					proc.IsSystem = uid == 0
				}
			}
		}
	}

	return proc, nil
}

// GetMemoryRegions returns memory regions for a process
func (r *LinuxReader) GetMemoryRegions(pid int) ([]models.MemoryRegion, error) {
	var regions []models.MemoryRegion

	mapsPath := filepath.Join("/proc", strconv.Itoa(pid), "maps")
	file, err := os.Open(mapsPath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		region, err := r.parseMapsLine(line)
		if err != nil {
			continue
		}
		regions = append(regions, region)
	}

	return regions, scanner.Err()
}

// parseMapsLine parses a line from /proc/[pid]/maps
func (r *LinuxReader) parseMapsLine(line string) (models.MemoryRegion, error) {
	// Format: address perms offset dev inode pathname
	// Example: 7f1234567000-7f1234569000 r-xp 00000000 08:01 12345 /lib/x86_64-linux-gnu/libc.so.6

	var region models.MemoryRegion

	fields := strings.Fields(line)
	if len(fields) < 5 {
		return region, fmt.Errorf("invalid maps line")
	}

	// Parse address range
	addrParts := strings.Split(fields[0], "-")
	if len(addrParts) != 2 {
		return region, fmt.Errorf("invalid address format")
	}

	startAddr, err := strconv.ParseUint(addrParts[0], 16, 64)
	if err != nil {
		return region, err
	}
	endAddr, err := strconv.ParseUint(addrParts[1], 16, 64)
	if err != nil {
		return region, err
	}

	region.BaseAddress = startAddr
	region.Size = endAddr - startAddr

	// Parse permissions
	perms := fields[1]
	region.Protection = r.parsePermissions(perms)
	region.IsExecutable = strings.Contains(perms, "x")
	region.IsWritable = strings.Contains(perms, "w")

	// Determine region type
	if len(fields) >= 6 {
		region.MappedFile = fields[5]
		if strings.HasSuffix(region.MappedFile, ".so") ||
			strings.Contains(region.MappedFile, ".so.") ||
			strings.HasSuffix(region.MappedFile, ".py") ||
			region.MappedFile == "" {
			region.Type = models.RegionTypeImage
		} else {
			region.Type = models.RegionTypeMapped
		}
	} else {
		region.Type = models.RegionTypePrivate
		region.IsUnbacked = region.IsExecutable
	}

	// Check for special regions
	if strings.Contains(line, "[stack]") {
		region.Type = models.RegionTypeStack
	} else if strings.Contains(line, "[heap]") {
		region.Type = models.RegionTypeHeap
	}

	region.State = "Commit"

	return region, nil
}

// parsePermissions converts Linux permission string to our format
func (r *LinuxReader) parsePermissions(perms string) string {
	var result string
	if len(perms) >= 1 && perms[0] == 'r' {
		result += "R"
	}
	if len(perms) >= 2 && perms[1] == 'w' {
		result += "W"
	}
	if len(perms) >= 3 && perms[2] == 'x' {
		result += "X"
	}
	if result == "" {
		result = "-"
	}
	return result
}

// ReadMemory reads memory from a process
func (r *LinuxReader) ReadMemory(pid int, address uint64, size uint64) ([]byte, error) {
	memPath := filepath.Join("/proc", strconv.Itoa(pid), "mem")

	file, err := os.Open(memPath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	data := make([]byte, size)

	// Use process_vm_readv for better performance if available
	// Fall back to seeking and reading from /proc/[pid]/mem
	_, err = file.Seek(int64(address), 0)
	if err != nil {
		return nil, err
	}

	n, err := file.Read(data)
	if err != nil {
		return nil, err
	}

	return data[:n], nil
}

// ReadMemoryVM uses process_vm_readv syscall for better performance
func (r *LinuxReader) ReadMemoryVM(pid int, address uint64, size uint64) ([]byte, error) {
	data := make([]byte, size)

	localIov := syscall.Iovec{
		Base: &data[0],
		Len:  uint64(size),
	}

	remoteIov := syscall.Iovec{
		Base: (*byte)(nil), // Will be set via unsafe
		Len:  uint64(size),
	}
	// Note: Setting remoteIov.Base to address requires unsafe pointer conversion
	// For simplicity, using the file-based method above

	_ = localIov
	_ = remoteIov

	// Fall back to file-based reading
	return r.ReadMemory(pid, address, size)
}

// IsLSASS returns false on Linux (Windows-only concept)
func (r *LinuxReader) IsLSASS(pid int) bool {
	return false
}
