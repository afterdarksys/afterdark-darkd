package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sync"

	sdk "github.com/afterdarksys/afterdark-darkd/pkg/pluginsdk"
	"github.com/hashicorp/go-hclog"
)

type OsqueryManager struct {
	config    *Config
	cmd       *exec.Cmd
	mu        sync.Mutex
	running   bool
	pluginDir string
	logger    hclog.Logger
}

func NewManager(pluginDir string) *OsqueryManager {
	return &OsqueryManager{
		pluginDir: pluginDir,
		logger:    sdk.Logger("osquery-manager"),
	}
}

func (m *OsqueryManager) Configure(cfg *Config) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.config = cfg
}

func (m *OsqueryManager) Start(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.running {
		return fmt.Errorf("osqueryd is already running")
	}

	if m.config == nil {
		return fmt.Errorf("configuration not set")
	}

	// 1. Write secret to file
	secretPath := filepath.Join(m.pluginDir, "osquery.secret")
	if err := os.WriteFile(secretPath, []byte(m.config.EnrollSecret), 0600); err != nil {
		return fmt.Errorf("failed to write enroll secret: %w", err)
	}

	// 2. Prepare command
	args := m.config.GenerateFlags(secretPath)
	// Add pidfile to keep track
	pidFile := filepath.Join(m.pluginDir, "osqueryd.pid")
	args = append(args, "--pidfile="+pidFile)
	// Add database path to keep it contained
	dbPath := filepath.Join(m.pluginDir, "osquery.db")
	args = append(args, "--database_path="+dbPath)

	m.cmd = exec.CommandContext(context.Background(), m.config.BinaryPath, args...) // Use background context so it doesn't die if Start ctx is cancelled?
	// Actually BaseServicePlugin calls Start with a context that might be cancelled on Stop.
	// But typically we want the process to run until WE stop it.
	// Let's use the passed context for startup, but manage the process independently?
	// Usually plugins run until Stop() is called.
	// For now, let's use a fresh command that we kill in Stop().
	m.cmd = exec.Command(m.config.BinaryPath, args...)

	// Redirect logs?
	// m.cmd.Stdout = ...
	// m.cmd.Stderr = ...

	m.logger.Info("Starting osqueryd", "path", m.config.BinaryPath, "args", args)

	if err := m.cmd.Start(); err != nil {
		return fmt.Errorf("failed to start osqueryd: %w", err)
	}

	m.running = true

	// Monitor in background
	go func() {
		err := m.cmd.Wait()
		m.mu.Lock()
		defer m.mu.Unlock()
		m.running = false
		m.logger.Warn("osqueryd exited", "error", err)
	}()

	return nil
}

func (m *OsqueryManager) Stop(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if !m.running || m.cmd == nil {
		return nil
	}

	m.logger.Info("Stopping osqueryd")

	// Try graceful interrupt
	if err := m.cmd.Process.Signal(os.Interrupt); err != nil {
		m.logger.Warn("failed to send interrupt", "error", err)
		// Fallback to kill
		m.cmd.Process.Kill()
	}

	// Wait for a bit (rudimentary)
	// In a real implementation we might wait on a channel from the monitor goroutine

	m.running = false
	return nil
}

func (m *OsqueryManager) Status() map[string]interface{} {
	m.mu.Lock()
	defer m.mu.Unlock()

	status := map[string]interface{}{
		"running": m.running,
	}
	if m.running && m.cmd != nil && m.cmd.Process != nil {
		status["pid"] = m.cmd.Process.Pid
	}
	return status
}
