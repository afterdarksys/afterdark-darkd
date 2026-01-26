//go:build windows

package memscan

import (
	"strings"
	"syscall"
	"unsafe"

	"github.com/afterdarksys/afterdark-darkd/internal/models"
	"go.uber.org/zap"
	"golang.org/x/sys/windows"
)

// WindowsReader reads process memory on Windows
type WindowsReader struct {
	logger *zap.Logger
}

// NewWindowsReader creates a new Windows memory reader
func NewWindowsReader(logger *zap.Logger) (*WindowsReader, error) {
	return &WindowsReader{logger: logger.Named("windows-reader")}, nil
}

// ListProcesses returns list of running processes
func (r *WindowsReader) ListProcesses() ([]models.ScanProcessInfo, error) {
	var processes []models.ScanProcessInfo

	// Create snapshot of all processes
	snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return nil, err
	}
	defer windows.CloseHandle(snapshot)

	var entry windows.ProcessEntry32
	entry.Size = uint32(unsafe.Sizeof(entry))

	err = windows.Process32First(snapshot, &entry)
	if err != nil {
		return nil, err
	}

	for {
		proc := models.ScanProcessInfo{
			PID:  int(entry.ProcessID),
			PPID: int(entry.ParentProcessID),
			Name: windows.UTF16ToString(entry.ExeFile[:]),
		}

		// Get additional info if we have access
		if handle, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, entry.ProcessID); err == nil {
			// Get executable path
			var pathBuf [windows.MAX_PATH]uint16
			size := uint32(len(pathBuf))
			if err := windows.QueryFullProcessImageName(handle, 0, &pathBuf[0], &size); err == nil {
				proc.Path = windows.UTF16ToString(pathBuf[:size])
			}

			windows.CloseHandle(handle)
		}

		// Check if system process
		proc.IsSystem = proc.PID < 10 || strings.EqualFold(proc.Name, "System")

		processes = append(processes, proc)

		err = windows.Process32Next(snapshot, &entry)
		if err != nil {
			break
		}
	}

	return processes, nil
}

// GetProcessInfo returns details for a PID
func (r *WindowsReader) GetProcessInfo(pid int) (*models.ScanProcessInfo, error) {
	// Re-use ListProcesses logic or optimize for single PID
	// For now, simpler to just start with basic info and enhance

	proc := &models.ScanProcessInfo{
		PID: pid,
	}

	handle, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid))
	if err != nil {
		return nil, err
	}
	defer windows.CloseHandle(handle)

	// Get executable path
	var pathBuf [windows.MAX_PATH]uint16
	size := uint32(len(pathBuf))
	if err := windows.QueryFullProcessImageName(handle, 0, &pathBuf[0], &size); err == nil {
		proc.Path = windows.UTF16ToString(pathBuf[:size])
		parts := strings.Split(proc.Path, "\\")
		if len(parts) > 0 {
			proc.Name = parts[len(parts)-1]
		}
	}

	return proc, nil
}

// MEMORY_BASIC_INFORMATION structure
type memoryBasicInformation struct {
	BaseAddress       uintptr
	AllocationBase    uintptr
	AllocationProtect uint32
	RegionSize        uintptr
	State             uint32
	Protect           uint32
	Type              uint32
}

// Memory protection constants
const (
	pageExecute          = 0x10
	pageExecuteRead      = 0x20
	pageExecuteReadWrite = 0x40
	pageExecuteWriteCopy = 0x80
	pageReadOnly         = 0x02
	pageReadWrite        = 0x04
	pageWriteCopy        = 0x08

	memCommit  = 0x1000
	memReserve = 0x2000
	memFree    = 0x10000

	memImage   = 0x1000000
	memMapped  = 0x40000
	memPrivate = 0x20000
)

var (
	kernel32              = syscall.NewLazyDLL("kernel32.dll")
	procVirtualQueryEx    = kernel32.NewProc("VirtualQueryEx")
	procReadProcessMemory = kernel32.NewProc("ReadProcessMemory")
)

// GetMemoryRegions returns memory regions for a process
func (r *WindowsReader) GetMemoryRegions(pid int) ([]models.MemoryRegion, error) {
	var regions []models.MemoryRegion

	handle, err := windows.OpenProcess(
		windows.PROCESS_QUERY_INFORMATION|windows.PROCESS_VM_READ,
		false,
		uint32(pid),
	)
	if err != nil {
		return nil, err
	}
	defer windows.CloseHandle(handle)

	var address uintptr
	var mbi memoryBasicInformation

	for {
		ret, _, _ := procVirtualQueryEx.Call(
			uintptr(handle),
			address,
			uintptr(unsafe.Pointer(&mbi)),
			unsafe.Sizeof(mbi),
		)

		if ret == 0 {
			break
		}

		if mbi.State == memCommit {
			region := models.MemoryRegion{
				BaseAddress:  uint64(mbi.BaseAddress),
				Size:         uint64(mbi.RegionSize),
				Protection:   r.protectionToString(mbi.Protect),
				Type:         r.typeToString(mbi.Type),
				State:        r.stateToString(mbi.State),
				IsExecutable: r.isExecutable(mbi.Protect),
				IsWritable:   r.isWritable(mbi.Protect),
			}

			// Check if unbacked executable
			if region.IsExecutable && mbi.Type == memPrivate {
				region.IsUnbacked = true
			}

			regions = append(regions, region)
		}

		address = mbi.BaseAddress + mbi.RegionSize
	}

	return regions, nil
}

// ReadMemory reads memory from a process
func (r *WindowsReader) ReadMemory(pid int, address uint64, size uint64) ([]byte, error) {
	handle, err := windows.OpenProcess(
		windows.PROCESS_VM_READ,
		false,
		uint32(pid),
	)
	if err != nil {
		return nil, err
	}
	defer windows.CloseHandle(handle)

	data := make([]byte, size)
	var bytesRead uintptr

	ret, _, err := procReadProcessMemory.Call(
		uintptr(handle),
		uintptr(address),
		uintptr(unsafe.Pointer(&data[0])),
		uintptr(size),
		uintptr(unsafe.Pointer(&bytesRead)),
	)

	if ret == 0 {
		return nil, err
	}

	return data[:bytesRead], nil
}

// IsLSASS checks if the process is LSASS
func (r *WindowsReader) IsLSASS(pid int) bool {
	processes, err := r.ListProcesses()
	if err != nil {
		return false
	}

	for _, proc := range processes {
		if proc.PID == pid {
			return strings.EqualFold(proc.Name, "lsass.exe")
		}
	}

	return false
}

// protectionToString converts protection flags to string
func (r *WindowsReader) protectionToString(protect uint32) string {
	switch protect {
	case pageExecuteReadWrite:
		return models.ProtectionRWX
	case pageExecuteRead:
		return models.ProtectionRX
	case pageExecute:
		return models.ProtectionExecute
	case pageReadWrite:
		return models.ProtectionRW
	case pageReadOnly:
		return models.ProtectionRead
	default:
		return "-"
	}
}

// typeToString converts memory type to string
func (r *WindowsReader) typeToString(memType uint32) string {
	switch memType {
	case memImage:
		return models.RegionTypeImage
	case memMapped:
		return models.RegionTypeMapped
	case memPrivate:
		return models.RegionTypePrivate
	default:
		return "Unknown"
	}
}

// stateToString converts memory state to string
func (r *WindowsReader) stateToString(state uint32) string {
	switch state {
	case memCommit:
		return "Commit"
	case memReserve:
		return "Reserve"
	case memFree:
		return "Free"
	default:
		return "Unknown"
	}
}

// isExecutable checks if protection allows execution
func (r *WindowsReader) isExecutable(protect uint32) bool {
	return protect == pageExecute ||
		protect == pageExecuteRead ||
		protect == pageExecuteReadWrite ||
		protect == pageExecuteWriteCopy
}

// isWritable checks if protection allows writing
func (r *WindowsReader) isWritable(protect uint32) bool {
	return protect == pageReadWrite ||
		protect == pageExecuteReadWrite ||
		protect == pageWriteCopy ||
		protect == pageExecuteWriteCopy
}
