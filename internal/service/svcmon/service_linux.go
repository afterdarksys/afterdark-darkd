//go:build linux

package svcmon

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"

	"github.com/afterdarksys/afterdark-darkd/internal/models"
	"github.com/godbus/dbus/v5"
)

// SystemdUnit represents a systemd unit from D-Bus
type SystemdUnit struct {
	Name        string
	Description string
	LoadState   string
	ActiveState string
	SubState    string
	Following   string
	UnitPath    dbus.ObjectPath
	JobID       uint32
	JobType     string
	JobPath     dbus.ObjectPath
}

// scanLinuxNative scans services on Linux using D-Bus systemd API
// instead of exec.Command("systemctl", "list-units")
func (s *Service) scanLinuxNative() ([]models.SystemService, error) {
	conn, err := dbus.SystemBus()
	if err != nil {
		// Fallback to reading unit files directly
		return s.scanLinuxUnitFiles()
	}
	defer conn.Close()

	// Call org.freedesktop.systemd1.Manager.ListUnits
	obj := conn.Object("org.freedesktop.systemd1", "/org/freedesktop/systemd1")
	call := obj.Call("org.freedesktop.systemd1.Manager.ListUnits", 0)
	if call.Err != nil {
		return s.scanLinuxUnitFiles()
	}

	var units [][]interface{}
	if err := call.Store(&units); err != nil {
		return s.scanLinuxUnitFiles()
	}

	services := make([]models.SystemService, 0, len(units))
	for _, unit := range units {
		if len(unit) < 5 {
			continue
		}

		name, ok := unit[0].(string)
		if !ok || !strings.HasSuffix(name, ".service") {
			continue
		}

		description, _ := unit[1].(string)
		activeState, _ := unit[3].(string)
		subState, _ := unit[4].(string)

		status := "stopped"
		if activeState == "active" {
			status = "running"
		} else if activeState == "failed" {
			status = "failed"
		}

		svc := models.SystemService{
			Name:        strings.TrimSuffix(name, ".service"),
			DisplayName: description,
			Status:      status,
		}

		// Get additional info if running
		if status == "running" {
			svc.Status = subState // Use more specific state like "running" vs "exited"
		}

		services = append(services, svc)
	}

	return services, nil
}

// scanLinuxUnitFiles reads systemd unit files directly as fallback
func (s *Service) scanLinuxUnitFiles() ([]models.SystemService, error) {
	services := make([]models.SystemService, 0)
	seen := make(map[string]bool)

	unitPaths := []string{
		"/etc/systemd/system",
		"/lib/systemd/system",
		"/usr/lib/systemd/system",
	}

	for _, dir := range unitPaths {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}

		for _, entry := range entries {
			name := entry.Name()
			if !strings.HasSuffix(name, ".service") {
				continue
			}

			serviceName := strings.TrimSuffix(name, ".service")
			if seen[serviceName] {
				continue
			}
			seen[serviceName] = true

			svc := models.SystemService{
				Name:   serviceName,
				Status: "unknown",
			}

			// Try to determine if enabled
			symlinkPath := filepath.Join("/etc/systemd/system/multi-user.target.wants", name)
			if _, err := os.Stat(symlinkPath); err == nil {
				svc.Enabled = true
			}

			// Check if running via cgroup
			cgroupPath := filepath.Join("/sys/fs/cgroup/system.slice", name)
			if info, err := os.Stat(cgroupPath); err == nil && info.IsDir() {
				svc.Status = "running"
			}

			services = append(services, svc)
		}
	}

	return services, nil
}

// getLinuxServiceProperties gets detailed service properties via D-Bus
func (s *Service) getLinuxServiceProperties(name string) (map[string]interface{}, error) {
	conn, err := dbus.SystemBus()
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	unitPath := dbus.ObjectPath("/org/freedesktop/systemd1/unit/" + escapeUnitName(name+"_2eservice"))
	obj := conn.Object("org.freedesktop.systemd1", unitPath)

	call := obj.Call("org.freedesktop.DBus.Properties.GetAll", 0, "org.freedesktop.systemd1.Service")
	if call.Err != nil {
		return nil, call.Err
	}

	var props map[string]dbus.Variant
	if err := call.Store(&props); err != nil {
		return nil, err
	}

	result := make(map[string]interface{})
	for k, v := range props {
		result[k] = v.Value()
	}

	return result, nil
}

// escapeUnitName escapes a unit name for D-Bus object path
func escapeUnitName(name string) string {
	var result strings.Builder
	for _, c := range name {
		if (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') {
			result.WriteRune(c)
		} else {
			result.WriteString("_" + strings.ToLower(string(rune(c))))
		}
	}
	return result.String()
}

// ServiceStatus represents systemd service status from /run/systemd
type ServiceStatus struct {
	MainPID     int    `json:"MainPID"`
	ActiveState string `json:"ActiveState"`
	SubState    string `json:"SubState"`
}

// readServiceStatus reads status from /run/systemd/units/
func readServiceStatus(name string) (*ServiceStatus, error) {
	statusPath := filepath.Join("/run/systemd/units", "invocation:"+name+".service")
	data, err := os.ReadFile(statusPath)
	if err != nil {
		return nil, err
	}

	var status ServiceStatus
	if err := json.Unmarshal(data, &status); err != nil {
		return nil, err
	}

	return &status, nil
}
