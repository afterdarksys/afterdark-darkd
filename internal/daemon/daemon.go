package daemon

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/afterdarksys/afterdark-darkd/internal/models"
	"github.com/afterdarksys/afterdark-darkd/internal/service"
	"github.com/afterdarksys/afterdark-darkd/pkg/logging"
	"go.uber.org/zap"
)

// State represents the daemon's current state
type State int

const (
	StateInit State = iota
	StateStarting
	StateRunning
	StateStopping
	StateStopped
)

func (s State) String() string {
	switch s {
	case StateInit:
		return "init"
	case StateStarting:
		return "starting"
	case StateRunning:
		return "running"
	case StateStopping:
		return "stopping"
	case StateStopped:
		return "stopped"
	default:
		return "unknown"
	}
}

// Daemon represents the main daemon process
type Daemon struct {
	config   *models.Config
	registry *service.Registry
	state    State
	mu       sync.RWMutex
	logger   *zap.Logger

	// Shutdown handling
	shutdownCh chan struct{}
	doneCh     chan struct{}

	// PID file management
	pidFile string
}

// New creates a new daemon instance
func New(cfg *models.Config) (*Daemon, error) {
	if cfg == nil {
		cfg = models.DefaultConfig()
	}

	logger := logging.With(zap.String("component", "daemon"))

	return &Daemon{
		config:     cfg,
		registry:   service.NewRegistry(),
		state:      StateInit,
		logger:     logger,
		shutdownCh: make(chan struct{}),
		doneCh:     make(chan struct{}),
		pidFile:    cfg.Daemon.PIDFile,
	}, nil
}

// Config returns the daemon configuration
func (d *Daemon) Config() *models.Config {
	return d.config
}

// Registry returns the service registry
func (d *Daemon) Registry() *service.Registry {
	return d.registry
}

// State returns the current daemon state
func (d *Daemon) State() State {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.state
}

func (d *Daemon) setState(state State) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.state = state
}

// Start initializes and starts the daemon
func (d *Daemon) Start(ctx context.Context) error {
	d.setState(StateStarting)
	d.logger.Info("starting daemon")

	// Write PID file
	if err := d.writePIDFile(); err != nil {
		d.logger.Error("failed to write PID file", zap.Error(err))
		return fmt.Errorf("failed to write PID file: %w", err)
	}

	// Start all services
	if err := d.registry.StartAll(ctx); err != nil {
		d.logger.Error("failed to start services", zap.Error(err))
		d.removePIDFile()
		return fmt.Errorf("failed to start services: %w", err)
	}

	d.setState(StateRunning)
	d.logger.Info("daemon started successfully")

	return nil
}

// Stop gracefully shuts down the daemon
func (d *Daemon) Stop(ctx context.Context) error {
	d.setState(StateStopping)
	d.logger.Info("stopping daemon")

	// Signal shutdown
	close(d.shutdownCh)

	// Stop all services
	if err := d.registry.StopAll(ctx); err != nil {
		d.logger.Error("error stopping services", zap.Error(err))
	}

	// Remove PID file
	d.removePIDFile()

	d.setState(StateStopped)
	d.logger.Info("daemon stopped")
	close(d.doneCh)

	return nil
}

// Run starts the daemon and waits for shutdown signal
func (d *Daemon) Run(ctx context.Context) error {
	if err := d.Start(ctx); err != nil {
		return err
	}

	// Set up signal handling
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)

	for {
		select {
		case sig := <-sigCh:
			switch sig {
			case syscall.SIGHUP:
				d.logger.Info("received SIGHUP, reloading configuration")
				if err := d.Reload(ctx); err != nil {
					d.logger.Error("failed to reload configuration", zap.Error(err))
				}
			case syscall.SIGINT, syscall.SIGTERM:
				d.logger.Info("received shutdown signal", zap.String("signal", sig.String()))
				shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
				defer cancel()
				return d.Stop(shutdownCtx)
			}
		case <-ctx.Done():
			d.logger.Info("context cancelled, shutting down")
			shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			return d.Stop(shutdownCtx)
		case <-d.shutdownCh:
			return nil
		}
	}
}

// Reload reloads the daemon configuration
func (d *Daemon) Reload(ctx context.Context) error {
	d.logger.Info("reloading configuration")
	// TODO: Implement configuration reload
	return nil
}

// Wait blocks until the daemon has fully stopped
func (d *Daemon) Wait() {
	<-d.doneCh
}

// Health returns the health status of all services
func (d *Daemon) Health() map[string]service.HealthStatus {
	return d.registry.HealthCheck()
}

func (d *Daemon) writePIDFile() error {
	if d.pidFile == "" {
		return nil
	}

	pid := os.Getpid()
	return os.WriteFile(d.pidFile, []byte(fmt.Sprintf("%d\n", pid)), 0644)
}

func (d *Daemon) removePIDFile() {
	if d.pidFile == "" {
		return
	}
	if err := os.Remove(d.pidFile); err != nil && !os.IsNotExist(err) {
		d.logger.Warn("failed to remove PID file", zap.Error(err))
	}
}
