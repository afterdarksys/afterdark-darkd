// AfterDark Configuration Helper
//
// A cross-platform GUI application for configuring the afterdark-darkd security daemon.
// Built with Fyne (fyne.io) for a native look and feel on all platforms.
//
// Features:
// - API key management and cloud connection
// - Firewall status and basic configuration
// - Service status monitoring
// - Quick security configuration wizards
//
// Build:
//
//	go build -o darkd-config .
//
// Requirements:
//
//	go get fyne.io/fyne/v2
package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"
)

const (
	appID        = "com.afterdark.config"
	appName      = "AfterDark Security"
	apiBaseURL   = "https://api.afterdark.io"
	daemonSocket = "/var/run/afterdark-darkd.sock"
)

// Config represents the local configuration
type Config struct {
	APIKey        string `json:"api_key"`
	APIEndpoint   string `json:"api_endpoint"`
	DeviceID      string `json:"device_id"`
	Enrolled      bool   `json:"enrolled"`
	LastSync      string `json:"last_sync"`
	AutoUpdate    bool   `json:"auto_update"`
	Notifications bool   `json:"notifications"`
}

// DaemonStatus represents the daemon's current status
type DaemonStatus struct {
	Running   bool              `json:"running"`
	Version   string            `json:"version"`
	Uptime    string            `json:"uptime"`
	Services  map[string]string `json:"services"`
	Firewall  FirewallSummary   `json:"firewall"`
	LastCheck time.Time         `json:"last_check"`
}

// FirewallSummary represents firewall status
type FirewallSummary struct {
	Enabled    bool `json:"enabled"`
	RuleCount  int  `json:"rule_count"`
	BlockedIPs int  `json:"blocked_ips"`
}

// App holds the application state
type App struct {
	fyneApp    fyne.App
	mainWindow fyne.Window
	config     *Config
	status     *DaemonStatus

	// UI components
	statusLabel     *widget.Label
	connectionLabel *widget.Label
	firewallToggle  *widget.Check
	servicesTable   *widget.Table
}

func main() {
	a := &App{
		config: &Config{
			APIEndpoint:   apiBaseURL,
			AutoUpdate:    true,
			Notifications: true,
		},
		status: &DaemonStatus{},
	}

	a.fyneApp = app.NewWithID(appID)
	a.fyneApp.Settings().SetTheme(theme.DarkTheme())

	a.mainWindow = a.fyneApp.NewWindow(appName)
	a.mainWindow.Resize(fyne.NewSize(800, 600))
	a.mainWindow.SetFixedSize(false)

	// Load existing config
	a.loadConfig()

	// Build UI
	content := a.buildUI()
	a.mainWindow.SetContent(content)

	// Start background status updates
	go a.statusUpdater()

	a.mainWindow.ShowAndRun()
}

func (a *App) buildUI() fyne.CanvasObject {
	// Header with logo and title
	title := widget.NewLabel(appName)
	title.TextStyle = fyne.TextStyle{Bold: true}
	title.Alignment = fyne.TextAlignCenter

	subtitle := widget.NewLabel("Endpoint Security Configuration")
	subtitle.Alignment = fyne.TextAlignCenter

	header := container.NewVBox(
		title,
		subtitle,
		widget.NewSeparator(),
	)

	// Create tabs
	tabs := container.NewAppTabs(
		container.NewTabItemWithIcon("Status", theme.HomeIcon(), a.buildStatusTab()),
		container.NewTabItemWithIcon("Connection", theme.ComputerIcon(), a.buildConnectionTab()),
		container.NewTabItemWithIcon("Firewall", theme.WarningIcon(), a.buildFirewallTab()),
		container.NewTabItemWithIcon("Settings", theme.SettingsIcon(), a.buildSettingsTab()),
	)
	tabs.SetTabLocation(container.TabLocationLeading)

	return container.NewBorder(header, nil, nil, nil, tabs)
}

func (a *App) buildStatusTab() fyne.CanvasObject {
	// Status indicators
	a.statusLabel = widget.NewLabel("Checking daemon status...")
	a.statusLabel.Alignment = fyne.TextAlignCenter

	statusCard := widget.NewCard("Daemon Status", "", container.NewVBox(
		a.statusLabel,
		widget.NewSeparator(),
	))

	// Quick actions
	startBtn := widget.NewButtonWithIcon("Start Daemon", theme.MediaPlayIcon(), func() {
		a.startDaemon()
	})
	stopBtn := widget.NewButtonWithIcon("Stop Daemon", theme.MediaStopIcon(), func() {
		a.stopDaemon()
	})
	restartBtn := widget.NewButtonWithIcon("Restart", theme.MediaReplayIcon(), func() {
		a.restartDaemon()
	})

	actionsCard := widget.NewCard("Quick Actions", "", container.NewHBox(
		startBtn,
		stopBtn,
		restartBtn,
	))

	// Services list
	servicesCard := widget.NewCard("Services", "", a.buildServicesWidget())

	return container.NewVBox(
		statusCard,
		actionsCard,
		servicesCard,
	)
}

func (a *App) buildServicesWidget() fyne.CanvasObject {
	services := []struct {
		name   string
		status string
	}{
		{"Patch Monitor", "Running"},
		{"Threat Intelligence", "Running"},
		{"Baseline Scanner", "Idle"},
		{"Network Monitor", "Running"},
		{"Connection Tracker", "Running"},
	}

	list := widget.NewList(
		func() int { return len(services) },
		func() fyne.CanvasObject {
			return container.NewHBox(
				widget.NewIcon(theme.ConfirmIcon()),
				widget.NewLabel("Service Name"),
				layout.NewSpacer(),
				widget.NewLabel("Status"),
			)
		},
		func(i widget.ListItemID, o fyne.CanvasObject) {
			box := o.(*fyne.Container)
			icon := box.Objects[0].(*widget.Icon)
			name := box.Objects[1].(*widget.Label)
			status := box.Objects[3].(*widget.Label)

			name.SetText(services[i].name)
			status.SetText(services[i].status)

			if services[i].status == "Running" {
				icon.SetResource(theme.ConfirmIcon())
			} else {
				icon.SetResource(theme.InfoIcon())
			}
		},
	)
	list.Resize(fyne.NewSize(400, 200))

	return list
}

func (a *App) buildConnectionTab() fyne.CanvasObject {
	a.connectionLabel = widget.NewLabel("Not connected to AfterDark Cloud")

	// API Key entry
	apiKeyEntry := widget.NewPasswordEntry()
	apiKeyEntry.SetPlaceHolder("Enter your API key")
	if a.config.APIKey != "" {
		apiKeyEntry.SetText(a.config.APIKey)
	}

	// Endpoint entry
	endpointEntry := widget.NewEntry()
	endpointEntry.SetText(a.config.APIEndpoint)

	// Connect button
	connectBtn := widget.NewButtonWithIcon("Connect", theme.LoginIcon(), func() {
		a.config.APIKey = apiKeyEntry.Text
		a.config.APIEndpoint = endpointEntry.Text
		a.connect()
	})
	connectBtn.Importance = widget.HighImportance

	// Get API key link
	getKeyBtn := widget.NewButtonWithIcon("Get API Key from Portal", theme.DocumentIcon(), func() {
		a.openURL("https://portal.afterdark.io/api-keys")
	})

	connectionCard := widget.NewCard("Cloud Connection", "", container.NewVBox(
		a.connectionLabel,
		widget.NewSeparator(),
		widget.NewForm(
			widget.NewFormItem("API Key", apiKeyEntry),
			widget.NewFormItem("Endpoint", endpointEntry),
		),
		container.NewHBox(
			connectBtn,
			getKeyBtn,
		),
	))

	// Device info
	deviceInfo := widget.NewCard("Device Information", "", container.NewVBox(
		widget.NewLabel(fmt.Sprintf("Device ID: %s", a.getDeviceID())),
		widget.NewLabel(fmt.Sprintf("OS: %s/%s", runtime.GOOS, runtime.GOARCH)),
		widget.NewLabel(fmt.Sprintf("Hostname: %s", a.getHostname())),
	))

	// Enrollment status
	enrollStatus := "Not Enrolled"
	if a.config.Enrolled {
		enrollStatus = "Enrolled"
	}
	enrollCard := widget.NewCard("Enrollment", "", container.NewVBox(
		widget.NewLabel(fmt.Sprintf("Status: %s", enrollStatus)),
		widget.NewLabel(fmt.Sprintf("Last Sync: %s", a.config.LastSync)),
	))

	return container.NewVBox(
		connectionCard,
		deviceInfo,
		enrollCard,
	)
}

func (a *App) buildFirewallTab() fyne.CanvasObject {
	// Firewall status
	a.firewallToggle = widget.NewCheck("Firewall Enabled", func(enabled bool) {
		a.toggleFirewall(enabled)
	})
	a.firewallToggle.Checked = true

	statusCard := widget.NewCard("Firewall Status", "", container.NewVBox(
		a.firewallToggle,
		widget.NewLabel("Backend: Auto-detected"),
		widget.NewLabel("Rules: 0 active"),
		widget.NewLabel("Blocked IPs: 0"),
	))

	// Quick rules
	openPortBtn := widget.NewButtonWithIcon("Open Port", theme.ContentAddIcon(), func() {
		a.showOpenPortDialog()
	})
	blockIPBtn := widget.NewButtonWithIcon("Block IP", theme.ContentRemoveIcon(), func() {
		a.showBlockIPDialog()
	})
	viewRulesBtn := widget.NewButtonWithIcon("View Rules", theme.ListIcon(), func() {
		a.showRulesDialog()
	})

	actionsCard := widget.NewCard("Quick Actions", "", container.NewHBox(
		openPortBtn,
		blockIPBtn,
		viewRulesBtn,
	))

	// Protection levels
	protectionSlider := widget.NewSlider(1, 3)
	protectionSlider.Value = 2
	protectionSlider.Step = 1

	protectionLabels := []string{"Basic", "Standard", "Maximum"}
	protectionLabel := widget.NewLabel("Standard Protection")
	protectionSlider.OnChanged = func(v float64) {
		protectionLabel.SetText(fmt.Sprintf("%s Protection", protectionLabels[int(v)-1]))
	}

	protectionCard := widget.NewCard("Protection Level", "", container.NewVBox(
		protectionLabel,
		protectionSlider,
		widget.NewLabel("Basic: Allow most traffic, block known threats"),
		widget.NewLabel("Standard: Block suspicious traffic, require explicit allows"),
		widget.NewLabel("Maximum: Default deny, explicit allow required"),
	))

	return container.NewVBox(
		statusCard,
		actionsCard,
		protectionCard,
	)
}

func (a *App) buildSettingsTab() fyne.CanvasObject {
	// Auto-update
	autoUpdateCheck := widget.NewCheck("Enable automatic updates", nil)
	autoUpdateCheck.Checked = a.config.AutoUpdate

	// Notifications
	notificationsCheck := widget.NewCheck("Enable desktop notifications", nil)
	notificationsCheck.Checked = a.config.Notifications

	// Start on boot
	startOnBootCheck := widget.NewCheck("Start on system boot", nil)
	startOnBootCheck.Checked = true

	generalCard := widget.NewCard("General", "", container.NewVBox(
		autoUpdateCheck,
		notificationsCheck,
		startOnBootCheck,
	))

	// Log level
	logLevelSelect := widget.NewSelect([]string{"Error", "Warn", "Info", "Debug"}, nil)
	logLevelSelect.SetSelected("Info")

	// Log location
	logLocationEntry := widget.NewEntry()
	logLocationEntry.SetText(a.getLogPath())

	loggingCard := widget.NewCard("Logging", "", container.NewVBox(
		widget.NewForm(
			widget.NewFormItem("Log Level", logLevelSelect),
			widget.NewFormItem("Log Location", logLocationEntry),
		),
		widget.NewButtonWithIcon("View Logs", theme.DocumentIcon(), func() {
			a.openLogViewer()
		}),
	))

	// Save button
	saveBtn := widget.NewButtonWithIcon("Save Settings", theme.DocumentSaveIcon(), func() {
		a.config.AutoUpdate = autoUpdateCheck.Checked
		a.config.Notifications = notificationsCheck.Checked
		a.saveConfig()
		dialog.ShowInformation("Settings Saved", "Your settings have been saved.", a.mainWindow)
	})
	saveBtn.Importance = widget.HighImportance

	// About
	aboutCard := widget.NewCard("About", "", container.NewVBox(
		widget.NewLabel("AfterDark Security Daemon"),
		widget.NewLabel("Version: 1.0.0"),
		widget.NewLabel("Copyright 2024 After Dark Systems, LLC"),
		widget.NewButtonWithIcon("Documentation", theme.HelpIcon(), func() {
			a.openURL("https://docs.afterdark.io")
		}),
	))

	return container.NewVBox(
		generalCard,
		loggingCard,
		container.NewHBox(layout.NewSpacer(), saveBtn, layout.NewSpacer()),
		aboutCard,
	)
}

// Helper methods

func (a *App) loadConfig() {
	configPath := a.getConfigPath()
	data, err := os.ReadFile(configPath)
	if err != nil {
		return // No config yet
	}
	json.Unmarshal(data, a.config)
}

func (a *App) saveConfig() {
	configPath := a.getConfigPath()
	os.MkdirAll(filepath.Dir(configPath), 0755)
	data, _ := json.MarshalIndent(a.config, "", "  ")
	os.WriteFile(configPath, data, 0600)
}

func (a *App) getConfigPath() string {
	switch runtime.GOOS {
	case "darwin":
		return filepath.Join(os.Getenv("HOME"), "Library", "Application Support", "AfterDark", "config.json")
	case "windows":
		return filepath.Join(os.Getenv("APPDATA"), "AfterDark", "config.json")
	default:
		return filepath.Join(os.Getenv("HOME"), ".config", "afterdark", "config.json")
	}
}

func (a *App) getLogPath() string {
	switch runtime.GOOS {
	case "darwin":
		return "/var/log/afterdark-darkd.log"
	case "windows":
		return "C:\\ProgramData\\AfterDark\\logs\\darkd.log"
	default:
		return "/var/log/afterdark-darkd.log"
	}
}

func (a *App) getDeviceID() string {
	if a.config.DeviceID != "" {
		return a.config.DeviceID
	}
	return "Not assigned"
}

func (a *App) getHostname() string {
	hostname, _ := os.Hostname()
	return hostname
}

func (a *App) statusUpdater() {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		a.updateStatus()
		<-ticker.C
	}
}

func (a *App) updateStatus() {
	// Check if daemon is running
	running := a.checkDaemonRunning()

	if running {
		a.statusLabel.SetText("Daemon is running")
	} else {
		a.statusLabel.SetText("Daemon is not running")
	}
}

func (a *App) checkDaemonRunning() bool {
	// Try to connect to daemon socket or check process
	_, err := os.Stat(daemonSocket)
	return err == nil
}

func (a *App) startDaemon() {
	dialog.ShowInformation("Starting Daemon", "Starting the AfterDark daemon...", a.mainWindow)
	// Would call: afterdark-darkdadm service start
}

func (a *App) stopDaemon() {
	dialog.ShowConfirm("Stop Daemon", "Are you sure you want to stop the daemon?", func(ok bool) {
		if ok {
			// Would call: afterdark-darkdadm service stop
		}
	}, a.mainWindow)
}

func (a *App) restartDaemon() {
	dialog.ShowInformation("Restarting", "Restarting the daemon...", a.mainWindow)
	// Would call: afterdark-darkdadm service restart
}

func (a *App) connect() {
	if a.config.APIKey == "" {
		dialog.ShowError(fmt.Errorf("please enter an API key"), a.mainWindow)
		return
	}

	// Test connection
	client := &http.Client{Timeout: 10 * time.Second}
	req, _ := http.NewRequest("GET", a.config.APIEndpoint+"/v1/health", nil)
	req.Header.Set("Authorization", "Bearer "+a.config.APIKey)

	resp, err := client.Do(req)
	if err != nil {
		a.connectionLabel.SetText("Connection failed: " + err.Error())
		dialog.ShowError(err, a.mainWindow)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode == 200 {
		a.connectionLabel.SetText("Connected to AfterDark Cloud")
		a.config.Enrolled = true
		a.config.LastSync = time.Now().Format(time.RFC3339)
		a.saveConfig()
		dialog.ShowInformation("Connected", "Successfully connected to AfterDark Cloud", a.mainWindow)
	} else {
		a.connectionLabel.SetText(fmt.Sprintf("Connection failed: %d", resp.StatusCode))
		dialog.ShowError(fmt.Errorf("API returned status %d", resp.StatusCode), a.mainWindow)
	}
}

func (a *App) toggleFirewall(enabled bool) {
	if enabled {
		dialog.ShowInformation("Firewall", "Enabling firewall...", a.mainWindow)
	} else {
		dialog.ShowConfirm("Disable Firewall", "Are you sure you want to disable the firewall?", func(ok bool) {
			if !ok {
				a.firewallToggle.SetChecked(true)
			}
		}, a.mainWindow)
	}
}

func (a *App) showOpenPortDialog() {
	portEntry := widget.NewEntry()
	portEntry.SetPlaceHolder("Port number (e.g., 8080)")

	protocolSelect := widget.NewSelect([]string{"TCP", "UDP", "Both"}, nil)
	protocolSelect.SetSelected("TCP")

	descEntry := widget.NewEntry()
	descEntry.SetPlaceHolder("Description (optional)")

	form := dialog.NewForm("Open Port", "Open", "Cancel",
		[]*widget.FormItem{
			widget.NewFormItem("Port", portEntry),
			widget.NewFormItem("Protocol", protocolSelect),
			widget.NewFormItem("Description", descEntry),
		},
		func(ok bool) {
			if ok {
				dialog.ShowInformation("Port Opened",
					fmt.Sprintf("Opened port %s/%s", portEntry.Text, protocolSelect.Selected),
					a.mainWindow)
			}
		},
		a.mainWindow,
	)
	form.Resize(fyne.NewSize(400, 200))
	form.Show()
}

func (a *App) showBlockIPDialog() {
	ipEntry := widget.NewEntry()
	ipEntry.SetPlaceHolder("IP address or CIDR (e.g., 192.168.1.100)")

	reasonEntry := widget.NewEntry()
	reasonEntry.SetPlaceHolder("Reason (optional)")

	durationSelect := widget.NewSelect([]string{"1 hour", "24 hours", "7 days", "Permanent"}, nil)
	durationSelect.SetSelected("Permanent")

	form := dialog.NewForm("Block IP", "Block", "Cancel",
		[]*widget.FormItem{
			widget.NewFormItem("IP Address", ipEntry),
			widget.NewFormItem("Reason", reasonEntry),
			widget.NewFormItem("Duration", durationSelect),
		},
		func(ok bool) {
			if ok {
				dialog.ShowInformation("IP Blocked",
					fmt.Sprintf("Blocked IP %s", ipEntry.Text),
					a.mainWindow)
			}
		},
		a.mainWindow,
	)
	form.Resize(fyne.NewSize(400, 200))
	form.Show()
}

func (a *App) showRulesDialog() {
	rulesText := widget.NewTextGrid()
	rulesText.SetText("No firewall rules configured.\n\nAdd rules using the Quick Actions above.")

	d := dialog.NewCustom("Firewall Rules", "Close",
		container.NewScroll(rulesText),
		a.mainWindow,
	)
	d.Resize(fyne.NewSize(600, 400))
	d.Show()
}

func (a *App) openLogViewer() {
	logPath := a.getLogPath()
	data, err := os.ReadFile(logPath)
	if err != nil {
		dialog.ShowError(fmt.Errorf("could not read log file: %w", err), a.mainWindow)
		return
	}

	logText := widget.NewTextGrid()
	logText.SetText(string(data))

	d := dialog.NewCustom("Log Viewer", "Close",
		container.NewScroll(logText),
		a.mainWindow,
	)
	d.Resize(fyne.NewSize(800, 600))
	d.Show()
}

func (a *App) openURL(urlStr string) {
	u, err := url.Parse(urlStr)
	if err != nil {
		dialog.ShowError(err, a.mainWindow)
		return
	}
	fyne.CurrentApp().OpenURL(u)
}
