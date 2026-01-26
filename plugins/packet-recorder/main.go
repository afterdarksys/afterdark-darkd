// Packet Recorder Plugin for afterdark-darkd
//
// Wraps the packetrecorderd binary to provide packet capture capabilities
// as a managed service within the AfterDark Security Suite.
//
// Build: go build -o packet-recorder .
// Install: cp packet-recorder /var/lib/afterdark-darkd/plugins/
package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	sdk "github.com/afterdarksys/afterdark-darkd/pkg/pluginsdk"
)

// PacketRecorderPlugin implements the ServicePlugin interface
type PacketRecorderPlugin struct {
	sdk.BaseServicePlugin

	mu            sync.Mutex
	cmd           *exec.Cmd
	binaryPath    string
	outputDir     string
	interfaceName string
	filter        string
	cancel        context.CancelFunc
	running       bool
	logger        func(string, ...interface{})
}

func (p *PacketRecorderPlugin) Info() sdk.PluginInfo {
	return sdk.PluginInfo{
		Name:        "packet-recorder",
		Version:     "1.0.0",
		Type:        sdk.PluginTypeService,
		Description: "Packet capture service wrapping packetrecorderd",
		Author:      "After Dark Systems, LLC",
		License:     "MIT",
		Capabilities: []string{
			"start_capture", "stop_capture", "status",
			"list_recordings", "get_recording",
		},
	}
}

func (p *PacketRecorderPlugin) Configure(config map[string]interface{}) error {
	if err := p.BaseServicePlugin.Configure(config); err != nil {
		return err
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	p.logger = func(format string, args ...interface{}) {
		fmt.Printf("[packet-recorder] "+format+"\n", args...)
	}

	// Defaults
	p.binaryPath = "packetrecorderd"
	p.outputDir = "/var/log/afterdark/captures"
	p.interfaceName = "en0"

	// Overrides from config
	if path, ok := config["binary_path"].(string); ok {
		p.binaryPath = path
	}
	if dir, ok := config["output_dir"].(string); ok {
		p.outputDir = dir
	}
	if iface, ok := config["interface"].(string); ok {
		p.interfaceName = iface
	}

	// Ensure output directory exists
	if err := os.MkdirAll(p.outputDir, 0755); err != nil {
		return fmt.Errorf("failed to create output directory: %w", err)
	}

	// Check if binary exists
	if _, err := exec.LookPath(p.binaryPath); err != nil {
		// Just warn, don't fail, maybe it's not in PATH yet
		p.logger("warning: packetrecorderd binary not found in PATH: %s", p.binaryPath)
	}

	p.SetState(sdk.PluginStateReady, "packet-recorder configured")
	return nil
}

func (p *PacketRecorderPlugin) Start(ctx context.Context) error {
	if err := p.BaseServicePlugin.Start(ctx); err != nil {
		return err
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	if p.running {
		return nil
	}

	// Prepare command
	// Usage: packetrecorderd --interface en0 --output /path/to/dir --filter "tcp port 80"
	args := []string{
		"--interface", p.interfaceName,
		"--output", p.outputDir,
	}

	if p.filter != "" {
		args = append(args, "--filter", p.filter)
	}

	cmdCtx, cancel := context.WithCancel(context.Background())
	p.cancel = cancel
	p.cmd = exec.CommandContext(cmdCtx, p.binaryPath, args...)

	// Redirect stdout/stderr to logger or file? For now just basic logging
	// In a real plugin, we might capture this
	p.cmd.Stdout = os.Stdout
	p.cmd.Stderr = os.Stderr

	p.logger("starting packetrecorderd with args: %v", args)
	if err := p.cmd.Start(); err != nil {
		cancel()
		return fmt.Errorf("failed to start packetrecorderd: %w", err)
	}

	p.running = true
	p.SetState(sdk.PluginStateRunning, fmt.Sprintf("capturing on %s", p.interfaceName))

	// Monitor process in background
	go func() {
		err := p.cmd.Wait()
		p.mu.Lock()
		defer p.mu.Unlock()

		p.running = false
		state := sdk.PluginStateStopped
		msg := "packetrecorderd exited"

		if err != nil {
			state = sdk.PluginStateError
			msg = fmt.Sprintf("packetrecorderd exited with error: %v", err)
			p.logger(msg)
		} else {
			p.logger(msg)
		}

		p.SetState(state, msg)
	}()

	return nil
}

func (p *PacketRecorderPlugin) Stop(ctx context.Context) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if !p.running || p.cmd == nil {
		return nil
	}

	p.logger("stopping packetrecorderd...")

	// Send SIGTERM
	if p.cmd.Process != nil {
		p.cmd.Process.Signal(syscall.SIGTERM)
	}

	// Wait briefly then cancel context (SIGKILL)
	done := make(chan error, 1)
	go func() {
		done <- p.cmd.Wait()
	}()

	select {
	case <-done:
		// Exited gracefully
	case <-time.After(5 * time.Second):
		// Timeout, force kill
		p.logger("packetrecorderd timeout, forcing kill")
		if p.cancel != nil {
			p.cancel()
		}
	}

	p.running = false
	p.SetState(sdk.PluginStateStopped, "stopped")

	return p.BaseServicePlugin.Stop(ctx)
}

func (p *PacketRecorderPlugin) Execute(ctx context.Context, action string, params map[string]interface{}) (map[string]interface{}, error) {
	switch action {
	case "status":
		return p.getStatus(), nil
	case "set_filter":
		if filter, ok := params["filter"].(string); ok {
			p.mu.Lock()
			p.filter = filter
			p.mu.Unlock()
			// Need to restart to apply filter? Assuming yes for now.
			// Ideally we'd signal the process or use a config reload.
			return map[string]interface{}{"status": "filter updated, restart to apply"}, nil
		}
		return nil, fmt.Errorf("missing filter parameter")
	case "list_recordings":
		return p.listRecordings()
	default:
		return nil, fmt.Errorf("unknown action: %s", action)
	}
}

func (p *PacketRecorderPlugin) getStatus() map[string]interface{} {
	p.mu.Lock()
	defer p.mu.Unlock()

	return map[string]interface{}{
		"running":    p.running,
		"interface":  p.interfaceName,
		"output_dir": p.outputDir,
		"filter":     p.filter,
		"pid":        p.getPid(),
	}
}

func (p *PacketRecorderPlugin) getPid() int {
	if p.cmd != nil && p.cmd.Process != nil {
		return p.cmd.Process.Pid
	}
	return 0
}

func (p *PacketRecorderPlugin) listRecordings() (map[string]interface{}, error) {
	p.mu.Lock()
	dir := p.outputDir
	p.mu.Unlock()

	files, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}

	var recordings []string
	for _, f := range files {
		if !f.IsDir() && filepath.Ext(f.Name()) == ".pcap" {
			recordings = append(recordings, f.Name())
		}
	}

	return map[string]interface{}{
		"recordings": recordings,
		"count":      len(recordings),
	}, nil
}

func main() {
	sdk.ServeServicePlugin(&PacketRecorderPlugin{})
}
