# Cross-Platform Implementation Guide

## Overview

AfterDark-DarkD supports five operating system platforms:
- macOS (Intel and Apple Silicon)
- Windows 10/11
- Red Hat Enterprise Linux (RHEL) / Rocky Linux
- Debian
- Ubuntu

This document provides platform-specific implementation details, build strategies, and testing approaches.

## Platform Detection Strategy

### Build Tags

Use Go build tags to separate platform-specific code:

```go
// File: internal/platform/patches_darwin.go
// +build darwin

package platform

// macOS-specific implementation

// File: internal/platform/patches_windows.go
// +build windows

package platform

// Windows-specific implementation

// File: internal/platform/patches_linux.go
// +build linux

package platform

// Linux-specific implementation (common code)

// File: internal/platform/patches_debian.go
// +build linux,debian

package platform

// Debian/Ubuntu-specific implementation

// File: internal/platform/patches_rhel.go
// +build linux,rhel

package platform

// RHEL/Rocky-specific implementation
```

### Runtime Detection

For Linux distributions, detect at runtime:

```go
// File: internal/platform/linux/detect.go
package linux

import (
    "os"
    "strings"
)

type Distro int

const (
    DistroUnknown Distro = iota
    DistroDebian
    DistroUbuntu
    DistroRHEL
    DistroRocky
    DistroCentOS
)

func DetectDistro() Distro {
    // Check /etc/os-release (modern approach)
    data, err := os.ReadFile("/etc/os-release")
    if err == nil {
        content := string(data)
        if strings.Contains(content, "ID=debian") {
            return DistroDebian
        }
        if strings.Contains(content, "ID=ubuntu") {
            return DistroUbuntu
        }
        if strings.Contains(content, "ID=\"rhel\"") || strings.Contains(content, "ID=rhel") {
            return DistroRHEL
        }
        if strings.Contains(content, "ID=\"rocky\"") || strings.Contains(content, "ID=rocky") {
            return DistroRocky
        }
    }

    // Fallback: check for package managers
    if _, err := os.Stat("/usr/bin/apt"); err == nil {
        return DistroDebian // Debian/Ubuntu
    }
    if _, err := os.Stat("/usr/bin/yum"); err == nil {
        return DistroRHEL // RHEL/Rocky/CentOS
    }
    if _, err := os.Stat("/usr/bin/dnf"); err == nil {
        return DistroRHEL // Modern RHEL/Rocky
    }

    return DistroUnknown
}

func (d Distro) String() string {
    switch d {
    case DistroDebian:
        return "debian"
    case DistroUbuntu:
        return "ubuntu"
    case DistroRHEL:
        return "rhel"
    case DistroRocky:
        return "rocky"
    case DistroCentOS:
        return "centos"
    default:
        return "unknown"
    }
}
```

## Platform-Specific Implementations

### 1. macOS Platform

#### System Information

```go
// File: internal/platform/macos/system.go
package macos

import (
    "bytes"
    "encoding/xml"
    "os/exec"
    "strings"
)

type SystemInfo struct {
    OSVersion    string
    BuildVersion string
    ModelName    string
    SerialNumber string
}

func GetSystemInfo() (*SystemInfo, error) {
    // Use system_profiler for detailed system information
    cmd := exec.Command("system_profiler", "SPSoftwareDataType", "SPHardwareDataType", "-xml")
    output, err := cmd.Output()
    if err != nil {
        return nil, err
    }

    // Parse XML output
    var plist SystemProfilerPlist
    if err := xml.Unmarshal(output, &plist); err != nil {
        return nil, err
    }

    info := &SystemInfo{}
    for _, item := range plist.Items {
        switch item.Type {
        case "SPSoftwareDataType":
            info.OSVersion = item.OSVersion
            info.BuildVersion = item.BuildVersion
        case "SPHardwareDataType":
            info.ModelName = item.ModelName
            info.SerialNumber = item.SerialNumber
        }
    }

    return info, nil
}

// Alternative: sysctl approach for kernel info
func GetKernelVersion() (string, error) {
    cmd := exec.Command("sysctl", "-n", "kern.osrelease")
    output, err := cmd.Output()
    if err != nil {
        return "", err
    }
    return strings.TrimSpace(string(output)), nil
}
```

#### Patch Management

```go
// File: internal/platform/macos/patches.go
package macos

import (
    "bytes"
    "encoding/xml"
    "os/exec"
    "time"
)

func ListAvailableUpdates() ([]Update, error) {
    // Use softwareupdate command
    cmd := exec.Command("softwareupdate", "--list", "--all")
    output, err := cmd.Output()
    if err != nil {
        return nil, err
    }

    return parseSoftwareUpdateList(output)
}

func InstallUpdate(updateID string) error {
    // Install specific update
    cmd := exec.Command("softwareupdate", "--install", updateID)
    return cmd.Run()
}

func InstallAllUpdates() error {
    // Install all available updates
    cmd := exec.Command("softwareupdate", "--install", "--all")
    return cmd.Run()
}

// Check if system update requires restart
func RequiresRestart(updateID string) (bool, error) {
    cmd := exec.Command("softwareupdate", "--list")
    output, err := cmd.Output()
    if err != nil {
        return false, err
    }

    // Parse output to check for "[restart]" marker
    return bytes.Contains(output, []byte("[restart]")), nil
}
```

#### Application Inventory

```go
// File: internal/platform/macos/apps.go
package macos

import (
    "os"
    "path/filepath"
    "time"
)

func ListApplications() ([]Application, error) {
    var apps []Application

    // Scan /Applications
    systemApps, err := scanApplicationsFolder("/Applications")
    if err == nil {
        apps = append(apps, systemApps...)
    }

    // Scan user Applications
    homeDir, _ := os.UserHomeDir()
    userApps, err := scanApplicationsFolder(filepath.Join(homeDir, "Applications"))
    if err == nil {
        apps = append(apps, userApps...)
    }

    // Also check Homebrew installations
    brewApps, err := listHomebrewPackages()
    if err == nil {
        apps = append(apps, brewApps...)
    }

    return apps, nil
}

func scanApplicationsFolder(dir string) ([]Application, error) {
    var apps []Application

    entries, err := os.ReadDir(dir)
    if err != nil {
        return nil, err
    }

    for _, entry := range entries {
        if !entry.IsDir() || !strings.HasSuffix(entry.Name(), ".app") {
            continue
        }

        appPath := filepath.Join(dir, entry.Name())
        info, err := readAppInfo(appPath)
        if err != nil {
            continue
        }

        apps = append(apps, info)
    }

    return apps, nil
}

func readAppInfo(appPath string) (Application, error) {
    // Read Info.plist from app bundle
    plistPath := filepath.Join(appPath, "Contents", "Info.plist")
    data, err := os.ReadFile(plistPath)
    if err != nil {
        return Application{}, err
    }

    var plist InfoPlist
    if err := plist.UnmarshalXML(data); err != nil {
        return Application{}, err
    }

    return Application{
        Name:    plist.CFBundleName,
        Version: plist.CFBundleShortVersionString,
        Vendor:  plist.CFBundleIdentifier,
        Path:    appPath,
    }, nil
}
```

#### Network Configuration

```go
// File: internal/platform/macos/network.go
package macos

import (
    "os/exec"
    "strings"
)

func SetDNSServers(servers []string) error {
    // Get active network service
    service, err := getActiveNetworkService()
    if err != nil {
        return err
    }

    // Set DNS servers
    args := []string{"-setdnsservers", service}
    args = append(args, servers...)

    cmd := exec.Command("networksetup", args...)
    return cmd.Run()
}

func getActiveNetworkService() (string, error) {
    cmd := exec.Command("networksetup", "-listallnetworkservices")
    output, err := cmd.Output()
    if err != nil {
        return "", err
    }

    // Parse output and find active service
    lines := strings.Split(string(output), "\n")
    for _, line := range lines {
        if strings.HasPrefix(line, "*") {
            continue // Disabled service
        }
        if line != "" && !strings.Contains(line, "An asterisk") {
            return line, nil
        }
    }

    return "Wi-Fi", nil // Default fallback
}

func GetPublicIP() (string, error) {
    // Query external service
    cmd := exec.Command("curl", "-s", "https://api.ipify.org")
    output, err := cmd.Output()
    if err != nil {
        return "", err
    }
    return strings.TrimSpace(string(output)), nil
}
```

### 2. Windows Platform

#### System Information

```go
// File: internal/platform/windows/system.go
// +build windows

package windows

import (
    "github.com/StackExchange/wmi"
)

type Win32_OperatingSystem struct {
    Caption           string
    Version           string
    BuildNumber       string
    OSArchitecture    string
    CSName            string
    InstallDate       time.Time
}

func GetSystemInfo() (*SystemInfo, error) {
    var os []Win32_OperatingSystem
    query := "SELECT Caption, Version, BuildNumber, OSArchitecture, CSName FROM Win32_OperatingSystem"

    if err := wmi.Query(query, &os); err != nil {
        return nil, err
    }

    if len(os) == 0 {
        return nil, errors.New("no OS information found")
    }

    return &SystemInfo{
        Name:         os[0].Caption,
        Version:      os[0].Version,
        Build:        os[0].BuildNumber,
        Architecture: os[0].OSArchitecture,
        Hostname:     os[0].CSName,
    }, nil
}
```

#### Patch Management (Windows Update)

```go
// File: internal/platform/windows/patches.go
// +build windows

package windows

import (
    "github.com/go-ole/go-ole"
    "github.com/go-ole/go-ole/oleutil"
)

type WindowsUpdateSession struct {
    session *ole.IDispatch
}

func NewUpdateSession() (*WindowsUpdateSession, error) {
    ole.CoInitialize(0)

    unknown, err := oleutil.CreateObject("Microsoft.Update.Session")
    if err != nil {
        return nil, err
    }

    session, err := unknown.QueryInterface(ole.IID_IDispatch)
    if err != nil {
        return nil, err
    }

    return &WindowsUpdateSession{session: session}, nil
}

func (s *WindowsUpdateSession) SearchUpdates() ([]Update, error) {
    // Create update searcher
    searcherObj, err := oleutil.CallMethod(s.session, "CreateUpdateSearcher")
    if err != nil {
        return nil, err
    }
    searcher := searcherObj.ToIDispatch()
    defer searcher.Release()

    // Search for updates
    criteria := "IsInstalled=0 and Type='Software'"
    searchResultObj, err := oleutil.CallMethod(searcher, "Search", criteria)
    if err != nil {
        return nil, err
    }
    searchResult := searchResultObj.ToIDispatch()
    defer searchResult.Release()

    // Get update collection
    updatesObj, err := oleutil.GetProperty(searchResult, "Updates")
    if err != nil {
        return nil, err
    }
    updates := updatesObj.ToIDispatch()
    defer updates.Release()

    // Get count
    countObj, err := oleutil.GetProperty(updates, "Count")
    if err != nil {
        return nil, err
    }
    count := int(countObj.Val)

    var results []Update
    for i := 0; i < count; i++ {
        itemObj, err := oleutil.CallMethod(updates, "Item", i)
        if err != nil {
            continue
        }
        item := itemObj.ToIDispatch()

        update, err := parseUpdate(item)
        item.Release()
        if err != nil {
            continue
        }

        results = append(results, update)
    }

    return results, nil
}

func (s *WindowsUpdateSession) InstallUpdate(updateID string) error {
    // Create update installer
    // Download and install the update
    // Implementation details...
    return nil
}

func (s *WindowsUpdateSession) Close() {
    if s.session != nil {
        s.session.Release()
    }
    ole.CoUninitialize()
}
```

#### Application Inventory (Registry)

```go
// File: internal/platform/windows/apps.go
// +build windows

package windows

import (
    "golang.org/x/sys/windows/registry"
)

func ListInstalledApplications() ([]Application, error) {
    var apps []Application

    // Check both 32-bit and 64-bit registry locations
    paths := []string{
        `SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`,
        `SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall`,
    }

    for _, path := range paths {
        pathApps, err := scanRegistryPath(path)
        if err != nil {
            continue
        }
        apps = append(apps, pathApps...)
    }

    return apps, nil
}

func scanRegistryPath(path string) ([]Application, error) {
    var apps []Application

    key, err := registry.OpenKey(registry.LOCAL_MACHINE, path, registry.ENUMERATE_SUB_KEYS)
    if err != nil {
        return nil, err
    }
    defer key.Close()

    subkeys, err := key.ReadSubKeyNames(-1)
    if err != nil {
        return nil, err
    }

    for _, subkey := range subkeys {
        app, err := readApplicationInfo(path, subkey)
        if err != nil {
            continue
        }
        if app.Name != "" {
            apps = append(apps, app)
        }
    }

    return apps, nil
}

func readApplicationInfo(basePath, subkey string) (Application, error) {
    fullPath := basePath + `\` + subkey
    key, err := registry.OpenKey(registry.LOCAL_MACHINE, fullPath, registry.QUERY_VALUE)
    if err != nil {
        return Application{}, err
    }
    defer key.Close()

    name, _, _ := key.GetStringValue("DisplayName")
    version, _, _ := key.GetStringValue("DisplayVersion")
    publisher, _, _ := key.GetStringValue("Publisher")
    installDate, _, _ := key.GetStringValue("InstallDate")
    installLocation, _, _ := key.GetStringValue("InstallLocation")

    return Application{
        Name:    name,
        Version: version,
        Vendor:  publisher,
        Path:    installLocation,
        // Parse installDate if available
    }, nil
}
```

#### Network Configuration

```go
// File: internal/platform/windows/network.go
// +build windows

package windows

import (
    "os/exec"
    "strings"
)

func SetDNSServers(interfaceName string, servers []string) error {
    // Use netsh command
    // First, set to static
    cmd := exec.Command("netsh", "interface", "ip", "set", "dns", interfaceName, "static", servers[0])
    if err := cmd.Run(); err != nil {
        return err
    }

    // Add additional DNS servers
    for i := 1; i < len(servers); i++ {
        cmd := exec.Command("netsh", "interface", "ip", "add", "dns", interfaceName, servers[i], "index="+strconv.Itoa(i+1))
        if err := cmd.Run(); err != nil {
            return err
        }
    }

    return nil
}

// Alternative: PowerShell approach
func SetDNSServersPowerShell(servers []string) error {
    serversStr := strings.Join(servers, ",")
    script := fmt.Sprintf(`Set-DnsClientServerAddress -InterfaceAlias "Ethernet" -ServerAddresses "%s"`, serversStr)

    cmd := exec.Command("powershell", "-Command", script)
    return cmd.Run()
}

func GetActiveInterfaces() ([]NetworkInterface, error) {
    // Use WMI to query network adapters
    type Win32_NetworkAdapterConfiguration struct {
        Description    string
        MACAddress     string
        IPAddress      []string
        IPEnabled      bool
    }

    var configs []Win32_NetworkAdapterConfiguration
    query := "SELECT Description, MACAddress, IPAddress, IPEnabled FROM Win32_NetworkAdapterConfiguration WHERE IPEnabled = TRUE"

    if err := wmi.Query(query, &configs); err != nil {
        return nil, err
    }

    var interfaces []NetworkInterface
    for _, config := range configs {
        if len(config.IPAddress) > 0 {
            interfaces = append(interfaces, NetworkInterface{
                Name:       config.Description,
                MACAddress: config.MACAddress,
                IPAddress:  config.IPAddress[0],
                Status:     "up",
            })
        }
    }

    return interfaces, nil
}
```

### 3. Linux Platform (Debian/Ubuntu)

#### Patch Management

```go
// File: internal/platform/linux/debian.go
// +build linux

package linux

import (
    "bufio"
    "bytes"
    "os/exec"
    "strings"
)

func ListAvailableUpdates() ([]Update, error) {
    // Update package cache first
    if err := updatePackageCache(); err != nil {
        return nil, err
    }

    // List upgradable packages
    cmd := exec.Command("apt", "list", "--upgradable")
    output, err := cmd.Output()
    if err != nil {
        return nil, err
    }

    return parseAptList(output)
}

func updatePackageCache() error {
    cmd := exec.Command("apt-get", "update")
    return cmd.Run()
}

func parseAptList(output []byte) ([]Update, error) {
    var updates []Update

    scanner := bufio.NewScanner(bytes.NewReader(output))
    for scanner.Scan() {
        line := scanner.Text()
        if strings.HasPrefix(line, "Listing...") {
            continue
        }

        parts := strings.Fields(line)
        if len(parts) < 3 {
            continue
        }

        update := Update{
            Name:           parts[0],
            CurrentVersion: parts[1],
            NewVersion:     parts[2],
        }

        // Check if security update
        if isSecurityUpdate(update.Name) {
            update.Category = "security"
            update.Severity = determineSeverity(update.Name)
        }

        updates = append(updates, update)
    }

    return updates, nil
}

func isSecurityUpdate(packageName string) bool {
    // Check unattended-upgrades security origins
    cmd := exec.Command("apt-cache", "policy", packageName)
    output, err := cmd.Output()
    if err != nil {
        return false
    }

    return bytes.Contains(output, []byte("security"))
}

func InstallUpdate(packageName string) error {
    cmd := exec.Command("apt-get", "install", "-y", packageName)
    return cmd.Run()
}

func InstallSecurityUpdates() error {
    // Use unattended-upgrades
    cmd := exec.Command("unattended-upgrade", "-d")
    return cmd.Run()
}
```

#### Application Inventory

```go
// File: internal/platform/linux/apps_debian.go
// +build linux

package linux

import (
    "bufio"
    "bytes"
    "os/exec"
    "strings"
)

func ListInstalledPackages() ([]Application, error) {
    cmd := exec.Command("dpkg-query", "-W", "-f", "${Package}\t${Version}\t${Architecture}\t${Installed-Size}\n")
    output, err := cmd.Output()
    if err != nil {
        return nil, err
    }

    return parseDpkgOutput(output)
}

func parseDpkgOutput(output []byte) ([]Application, error) {
    var apps []Application

    scanner := bufio.NewScanner(bytes.NewReader(output))
    for scanner.Scan() {
        line := scanner.Text()
        parts := strings.Split(line, "\t")
        if len(parts) < 2 {
            continue
        }

        app := Application{
            Name:    parts[0],
            Version: parts[1],
        }

        if len(parts) > 2 {
            app.Architecture = parts[2]
        }

        apps = append(apps, app)
    }

    return apps, nil
}
```

### 4. Linux Platform (RHEL/Rocky)

#### Patch Management

```go
// File: internal/platform/linux/rhel.go
// +build linux

package linux

import (
    "bufio"
    "bytes"
    "os/exec"
    "strings"
)

func ListAvailableUpdates() ([]Update, error) {
    // Check for updates using yum/dnf
    cmd := exec.Command("dnf", "check-update", "--quiet")
    output, err := cmd.CombinedOutput()
    // Note: dnf returns exit code 100 when updates are available
    if err != nil && !strings.Contains(err.Error(), "exit status 100") {
        return nil, err
    }

    return parseDnfCheckUpdate(output)
}

func parseDnfCheckUpdate(output []byte) ([]Update, error) {
    var updates []Update

    scanner := bufio.NewScanner(bytes.NewReader(output))
    for scanner.Scan() {
        line := scanner.Text()
        if strings.TrimSpace(line) == "" {
            continue
        }

        parts := strings.Fields(line)
        if len(parts) < 3 {
            continue
        }

        update := Update{
            Name:       parts[0],
            NewVersion: parts[1],
            Repository: parts[2],
        }

        // Determine if security update
        if strings.Contains(update.Repository, "security") {
            update.Category = "security"
        }

        updates = append(updates, update)
    }

    return updates, nil
}

func ListSecurityUpdates() ([]Update, error) {
    cmd := exec.Command("dnf", "updateinfo", "list", "security", "--quiet")
    output, err := cmd.Output()
    if err != nil {
        return nil, err
    }

    return parseDnfSecurityUpdates(output)
}

func InstallSecurityUpdates() error {
    cmd := exec.Command("dnf", "update", "-y", "--security")
    return cmd.Run()
}
```

## Service Management

### macOS (launchd)

```xml
<!-- File: scripts/service/launchd/com.afterdarksys.darkd.plist -->
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.afterdarksys.darkd</string>

    <key>ProgramArguments</key>
    <array>
        <string>/usr/local/bin/afterdark-darkd</string>
        <string>--config</string>
        <string>/etc/afterdark/darkd.yaml</string>
    </array>

    <key>RunAtLoad</key>
    <true/>

    <key>KeepAlive</key>
    <dict>
        <key>SuccessfulExit</key>
        <false/>
    </dict>

    <key>StandardOutPath</key>
    <string>/var/log/afterdark/darkd.log</string>

    <key>StandardErrorPath</key>
    <string>/var/log/afterdark/darkd.error.log</string>

    <key>EnvironmentVariables</key>
    <dict>
        <key>PATH</key>
        <string>/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin</string>
    </dict>
</dict>
</plist>
```

Installation:
```bash
sudo cp com.afterdarksys.darkd.plist /Library/LaunchDaemons/
sudo launchctl load /Library/LaunchDaemons/com.afterdarksys.darkd.plist
sudo launchctl start com.afterdarksys.darkd
```

### Windows (Service)

```go
// File: internal/platform/windows/service.go
// +build windows

package windows

import (
    "golang.org/x/sys/windows/svc"
    "golang.org/x/sys/windows/svc/mgr"
)

type DarkdService struct {
    daemon *daemon.Daemon
}

func (s *DarkdService) Execute(args []string, r <-chan svc.ChangeRequest, changes chan<- svc.Status) (bool, uint32) {
    const cmdsAccepted = svc.AcceptStop | svc.AcceptShutdown

    changes <- svc.Status{State: svc.StartPending}

    // Start daemon
    if err := s.daemon.Start(context.Background()); err != nil {
        return true, 1
    }

    changes <- svc.Status{State: svc.Running, Accepts: cmdsAccepted}

    for {
        select {
        case c := <-r:
            switch c.Cmd {
            case svc.Stop, svc.Shutdown:
                changes <- svc.Status{State: svc.StopPending}
                s.daemon.Stop(context.Background())
                return false, 0
            }
        }
    }
}

func InstallService() error {
    m, err := mgr.Connect()
    if err != nil {
        return err
    }
    defer m.Disconnect()

    exePath, err := os.Executable()
    if err != nil {
        return err
    }

    s, err := m.CreateService("AfterDarkDarkd", exePath, mgr.Config{
        DisplayName: "AfterDark Security Daemon",
        Description: "Endpoint security monitoring and compliance",
        StartType:   mgr.StartAutomatic,
    })
    if err != nil {
        return err
    }
    defer s.Close()

    return nil
}
```

### Linux (systemd)

```ini
# File: scripts/service/systemd/afterdark-darkd.service
[Unit]
Description=AfterDark Security Daemon
After=network.target

[Service]
Type=simple
User=root
ExecStart=/usr/local/bin/afterdark-darkd --config /etc/afterdark/darkd.yaml
Restart=on-failure
RestartSec=10
StandardOutput=journal
StandardError=journal

# Security hardening
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/afterdark /var/log/afterdark

[Install]
WantedBy=multi-user.target
```

Installation:
```bash
sudo cp afterdark-darkd.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable afterdark-darkd
sudo systemctl start afterdark-darkd
```

## Build Matrix

### Cross-Compilation

```bash
# macOS Intel
GOOS=darwin GOARCH=amd64 go build -o dist/afterdark-darkd-darwin-amd64

# macOS Apple Silicon
GOOS=darwin GOARCH=arm64 go build -o dist/afterdark-darkd-darwin-arm64

# Windows
GOOS=windows GOARCH=amd64 go build -o dist/afterdark-darkd-windows-amd64.exe

# Linux AMD64
GOOS=linux GOARCH=amd64 go build -o dist/afterdark-darkd-linux-amd64

# Linux ARM64 (for ARM servers)
GOOS=linux GOARCH=arm64 go build -o dist/afterdark-darkd-linux-arm64
```

### CI/CD Build Matrix (GitHub Actions)

```yaml
# File: .github/workflows/build.yml
name: Build

on: [push, pull_request]

jobs:
  build:
    runs-on: ${{ matrix.os }}
    strategy:
      matrix:
        os: [ubuntu-latest, macos-latest, windows-latest]
        go: ['1.21']

    steps:
    - uses: actions/checkout@v3

    - name: Set up Go
      uses: actions/setup-go@v4
      with:
        go-version: ${{ matrix.go }}

    - name: Build
      run: make build

    - name: Test
      run: make test

    - name: Upload artifacts
      uses: actions/upload-artifact@v3
      with:
        name: binaries-${{ matrix.os }}
        path: |
          afterdark-darkd*
          afterdark-darkdadm*
          darkapi*
```

## Testing Strategy

### Platform-Specific Tests

```go
// File: test/platform/macos_test.go
// +build darwin

package platform_test

import (
    "testing"
    "github.com/afterdarksys/afterdark-darkd/internal/platform/macos"
)

func TestMacOS_ListUpdates(t *testing.T) {
    updates, err := macos.ListAvailableUpdates()
    if err != nil {
        t.Fatalf("Failed to list updates: %v", err)
    }

    t.Logf("Found %d updates", len(updates))
}

// File: test/platform/windows_test.go
// +build windows

package platform_test

import (
    "testing"
    "github.com/afterdarksys/afterdark-darkd/internal/platform/windows"
)

func TestWindows_ListUpdates(t *testing.T) {
    session, err := windows.NewUpdateSession()
    if err != nil {
        t.Fatalf("Failed to create session: %v", err)
    }
    defer session.Close()

    updates, err := session.SearchUpdates()
    if err != nil {
        t.Fatalf("Failed to search updates: %v", err)
    }

    t.Logf("Found %d updates", len(updates))
}
```

### Docker-based Linux Testing

```dockerfile
# File: test/docker/debian/Dockerfile
FROM debian:12

RUN apt-get update && apt-get install -y \
    ca-certificates \
    curl

COPY afterdark-darkd /usr/local/bin/
COPY configs/darkd.yaml /etc/afterdark/

CMD ["/usr/local/bin/afterdark-darkd", "--config", "/etc/afterdark/darkd.yaml"]
```

## Privilege Management

### Required Privileges by Platform

| Platform | Installation | Runtime | Patch Install | Network Config |
|----------|-------------|---------|---------------|----------------|
| macOS | root/sudo | root | root | root |
| Windows | Administrator | SYSTEM | SYSTEM | Administrator |
| Linux | root | root | root | root |

### Privilege Escalation

```go
// File: internal/platform/privilege.go
package platform

import (
    "os"
    "runtime"
)

func RequireRoot() error {
    if runtime.GOOS == "windows" {
        return requireAdministrator()
    }

    if os.Geteuid() != 0 {
        return errors.New("this program must be run as root")
    }

    return nil
}

func requireAdministrator() error {
    // Windows-specific check
    // Implementation using Windows API
    return nil
}
```

## File Paths by Platform

```go
// File: internal/daemon/paths.go
package daemon

import "runtime"

type Paths struct {
    ConfigDir string
    DataDir   string
    LogDir    string
    RunDir    string
    Socket    string
}

func DefaultPaths() Paths {
    switch runtime.GOOS {
    case "darwin":
        return Paths{
            ConfigDir: "/etc/afterdark",
            DataDir:   "/var/lib/afterdark",
            LogDir:    "/var/log/afterdark",
            RunDir:    "/var/run/afterdark",
            Socket:    "/var/run/afterdark/darkd.sock",
        }
    case "windows":
        return Paths{
            ConfigDir: `C:\ProgramData\AfterDark`,
            DataDir:   `C:\ProgramData\AfterDark\data`,
            LogDir:    `C:\ProgramData\AfterDark\logs`,
            RunDir:    `C:\ProgramData\AfterDark\run`,
            Socket:    `\\.\pipe\afterdark-darkd`,
        }
    default: // Linux
        return Paths{
            ConfigDir: "/etc/afterdark",
            DataDir:   "/var/lib/afterdark",
            LogDir:    "/var/log/afterdark",
            RunDir:    "/var/run/afterdark",
            Socket:    "/var/run/afterdark/darkd.sock",
        }
    }
}
```

## Performance Considerations

### macOS
- `system_profiler` can be slow; cache results
- Use `mdfind` for fast file searching
- Leverage Grand Central Dispatch for concurrency

### Windows
- WMI queries can be expensive; batch when possible
- COM initialization is per-thread; use connection pools
- Registry operations are fast; prefer over WMI when possible

### Linux
- Package manager commands may lock; handle gracefully
- Parse `/proc` and `/sys` for fast system info
- Use `apt-cache` / `dnf info` for cached package data

## Summary

This cross-platform implementation provides:
1. Unified interface with platform-specific implementations
2. Build tags for compile-time platform selection
3. Runtime detection for Linux distributions
4. Platform-appropriate service management
5. Comprehensive testing strategy
6. Optimized performance per platform
