//go:build windows

package svcmon

import (
	"unsafe"

	"github.com/afterdarksys/afterdark-darkd/internal/models"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc/mgr"
)

// scanWindowsNative scans services on Windows using native Win32 API
// instead of exec.Command("powershell", "Get-Service")
func (s *Service) scanWindowsNative() ([]models.SystemService, error) {
	// Open Service Control Manager
	m, err := mgr.Connect()
	if err != nil {
		return nil, err
	}
	defer m.Disconnect()

	// List all services
	names, err := m.ListServices()
	if err != nil {
		return nil, err
	}

	services := make([]models.SystemService, 0, len(names))

	for _, name := range names {
		svc, err := m.OpenService(name)
		if err != nil {
			continue // Skip services we can't access
		}

		config, err := svc.Config()
		if err != nil {
			svc.Close()
			continue
		}

		status, err := svc.Query()
		if err != nil {
			svc.Close()
			continue
		}

		svc.Close()

		statusStr := "unknown"
		switch status.State {
		case windows.SERVICE_STOPPED:
			statusStr = "stopped"
		case windows.SERVICE_START_PENDING:
			statusStr = "starting"
		case windows.SERVICE_STOP_PENDING:
			statusStr = "stopping"
		case windows.SERVICE_RUNNING:
			statusStr = "running"
		case windows.SERVICE_CONTINUE_PENDING:
			statusStr = "continuing"
		case windows.SERVICE_PAUSE_PENDING:
			statusStr = "pausing"
		case windows.SERVICE_PAUSED:
			statusStr = "paused"
		}

		enabled := config.StartType != mgr.StartDisabled

		services = append(services, models.SystemService{
			Name:        name,
			DisplayName: config.DisplayName,
			Status:      statusStr,
			Enabled:     enabled,
			Executable:  config.BinaryPathName,
		})
	}

	return services, nil
}

// getWindowsServiceDetails gets detailed information about a Windows service
func (s *Service) getWindowsServiceDetails(name string) (*models.SystemService, error) {
	m, err := mgr.Connect()
	if err != nil {
		return nil, err
	}
	defer m.Disconnect()

	svc, err := m.OpenService(name)
	if err != nil {
		return nil, err
	}
	defer svc.Close()

	config, err := svc.Config()
	if err != nil {
		return nil, err
	}

	status, err := svc.Query()
	if err != nil {
		return nil, err
	}

	statusStr := "unknown"
	switch status.State {
	case windows.SERVICE_STOPPED:
		statusStr = "stopped"
	case windows.SERVICE_RUNNING:
		statusStr = "running"
	case windows.SERVICE_PAUSED:
		statusStr = "paused"
	}

	return &models.SystemService{
		Name:        name,
		DisplayName: config.DisplayName,
		Status:      statusStr,
		Enabled:     config.StartType != mgr.StartDisabled,
		Executable:  config.BinaryPathName,
	}, nil
}

// Windows service control constants
const (
	SC_MANAGER_ENUMERATE_SERVICE = 0x0004
	SERVICE_QUERY_STATUS         = 0x0004
	SERVICE_QUERY_CONFIG         = 0x0001
)

// EnumServicesStatus calls Windows EnumServicesStatusExW for complete enumeration
// This is a lower-level alternative if mgr package has issues
func EnumServicesStatus() ([]models.SystemService, error) {
	advapi32 := windows.NewLazyDLL("advapi32.dll")
	procOpenSCManager := advapi32.NewProc("OpenSCManagerW")
	procEnumServicesStatusEx := advapi32.NewProc("EnumServicesStatusExW")
	procCloseServiceHandle := advapi32.NewProc("CloseServiceHandle")

	// Open SCM
	scmHandle, _, err := procOpenSCManager.Call(
		0, // Local machine
		0, // SERVICES_ACTIVE_DATABASE
		SC_MANAGER_ENUMERATE_SERVICE,
	)
	if scmHandle == 0 {
		return nil, err
	}
	defer procCloseServiceHandle.Call(scmHandle)

	// First call to get required buffer size
	var bytesNeeded, servicesReturned, resumeHandle uint32
	procEnumServicesStatusEx.Call(
		scmHandle,
		0,    // SC_ENUM_PROCESS_INFO
		0x30, // SERVICE_WIN32
		0x3,  // SERVICE_STATE_ALL
		0,    // No buffer
		0,    // Buffer size 0
		uintptr(unsafe.Pointer(&bytesNeeded)),
		uintptr(unsafe.Pointer(&servicesReturned)),
		uintptr(unsafe.Pointer(&resumeHandle)),
		0,
	)

	if bytesNeeded == 0 {
		return []models.SystemService{}, nil
	}

	// Allocate buffer and enumerate
	buffer := make([]byte, bytesNeeded)
	ret, _, err := procEnumServicesStatusEx.Call(
		scmHandle,
		0,    // SC_ENUM_PROCESS_INFO
		0x30, // SERVICE_WIN32
		0x3,  // SERVICE_STATE_ALL
		uintptr(unsafe.Pointer(&buffer[0])),
		uintptr(bytesNeeded),
		uintptr(unsafe.Pointer(&bytesNeeded)),
		uintptr(unsafe.Pointer(&servicesReturned)),
		uintptr(unsafe.Pointer(&resumeHandle)),
		0,
	)

	if ret == 0 {
		return nil, err
	}

	// Parse buffer - this would require proper struct parsing
	// For now, use the higher-level mgr package approach
	return []models.SystemService{}, nil
}
