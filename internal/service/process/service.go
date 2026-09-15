package process

import (
	"context"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/afterdarksys/afterdark-darkd/internal/models"
	"github.com/afterdarksys/afterdark-darkd/internal/service"
	"github.com/afterdarksys/afterdark-darkd/pkg/logging"
	gopsnet "github.com/shirou/gopsutil/v3/net"
	"github.com/shirou/gopsutil/v3/process"
	"go.uber.org/zap"
)

// Service monitors running processes
type Service struct {
	OnProcess func(models.Process)
	lifecycle sync.Mutex
	stopping  bool
	mu        sync.RWMutex
	config    *models.TrackingConfig
	running   bool
	cancel    context.CancelFunc
	logger    *zap.Logger

	observer      func(models.ProcessSnapshot)
	done          chan struct{}
	lastScan      time.Time
	lastScanError string

	// Current state
	processes    map[int32]*models.Process
	lastSnapshot *models.ProcessSnapshot

	// History for tracking
	history []models.ProcessSnapshot
}

// New creates a new process tracking service
func New(config *models.TrackingConfig) *Service {
	return &Service{
		config:    config,
		processes: make(map[int32]*models.Process),
		history:   make([]models.ProcessSnapshot, 0),
		logger:    logging.Get().Named("process"),
	}
}

// SetObserver attaches a local evidence sink before the service starts.
func (s *Service) SetObserver(observer func(models.ProcessSnapshot)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.observer = observer
}

// Name returns the service identifier
func (s *Service) Name() string {
	return "process_tracker"
}

// Start initializes and starts the service
func (s *Service) Start(ctx context.Context) error {
	s.lifecycle.Lock()
	defer s.lifecycle.Unlock()
	s.mu.Lock()
	if s.stopping {
		s.mu.Unlock()
		return fmt.Errorf("%s is still stopping", s.Name())
	}
	if s.running {
		s.mu.Unlock()
		return nil
	}

	s.running = true
	s.done = make(chan struct{})
	ctx, s.cancel = context.WithCancel(ctx)
	s.mu.Unlock()

	s.logger.Info("starting process tracker service",
		zap.Duration("interval", s.config.ProcessInterval))

	// Initial scan
	if err := s.scan(ctx); err != nil {
		s.logger.Warn("initial process scan failed", zap.Error(err))
	}

	// Start periodic scanning
	go s.runLoop(ctx)

	return nil
}

// Stop gracefully shuts down the service
func (s *Service) Stop(ctx context.Context) error {
	s.lifecycle.Lock()
	defer s.lifecycle.Unlock()
	s.mu.Lock()
	if !s.running {
		s.mu.Unlock()
		return nil
	}
	s.stopping = true
	s.cancel()
	done := s.done
	s.mu.Unlock()
	select {
	case <-done:
		s.mu.Lock()
		s.running = false
		s.stopping = false
		s.mu.Unlock()
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Health returns the current health status
func (s *Service) Health() service.HealthStatus {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if !s.running || s.stopping {
		return service.HealthStatus{
			Status:    service.HealthUnhealthy,
			Message:   "service not running",
			LastCheck: time.Now(),
		}
	}

	if s.lastScan.IsZero() || s.lastScanError != "" {
		return service.HealthStatus{Status: service.HealthDegraded, Message: "no successful scan or latest scan failed: " + s.lastScanError, LastCheck: time.Now()}
	}
	interval := s.config.ProcessInterval
	if interval <= 0 {
		interval = 30 * time.Second
	}
	if time.Since(s.lastScan) > 2*interval+30*time.Second {
		return service.HealthStatus{Status: service.HealthDegraded, Message: "sensor observations are stale", LastCheck: time.Now(), Metrics: map[string]interface{}{"last_successful_scan": s.lastScan}}
	}
	metrics := make(map[string]interface{})
	metrics["collection_method"] = "polling"
	metrics["last_successful_scan"] = s.lastScan
	if s.lastSnapshot != nil {
		metrics["total_processes"] = s.lastSnapshot.Summary.Total
		metrics["last_scan"] = s.lastSnapshot.Timestamp
	}

	return service.HealthStatus{
		Status:    service.HealthHealthy,
		Message:   "process tracking active",
		LastCheck: time.Now(),
		Metrics:   metrics,
	}
}

// Configure updates service configuration
func (s *Service) Configure(config interface{}) error {
	if cfg, ok := config.(*models.TrackingConfig); ok {
		s.mu.Lock()
		s.config = cfg
		s.mu.Unlock()
	}
	return nil
}

// runLoop runs the periodic process scan
func (s *Service) runLoop(ctx context.Context) {
	defer close(s.done)
	s.mu.RLock()
	interval := s.config.ProcessInterval
	s.mu.RUnlock()
	if interval <= 0 {
		interval = 30 * time.Second
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := s.scan(ctx); err != nil {
				s.logger.Warn("process scan failed", zap.Error(err))
			}
		}
	}
}

// scan collects current process information
func (s *Service) scan(ctx context.Context) (scanErr error) {
	defer func() {
		s.mu.Lock()
		defer s.mu.Unlock()
		if scanErr != nil {
			s.lastScanError = scanErr.Error()
		} else {
			s.lastScan = time.Now()
			s.lastScanError = ""
		}
	}()
	procs, err := process.ProcessesWithContext(ctx)
	if err != nil {
		return err
	}

	connections, _ := gopsnet.ConnectionsWithContext(ctx, "all")
	connectionCounts := make(map[int32]int)
	for _, conn := range connections {
		connectionCounts[conn.Pid]++
	}
	hostname, _ := os.Hostname()
	snapshot := models.ProcessSnapshot{
		Timestamp: time.Now(),
		Hostname:  hostname,
		Processes: make([]models.Process, 0, len(procs)),
	}

	var running, sleeping, zombie int
	var cpuTotal, memTotal float64

	newProcesses := make(map[int32]*models.Process)

	for _, p := range procs {
		if err := ctx.Err(); err != nil {
			return err
		}
		proc := s.processInfo(ctx, p)
		if proc == nil {
			continue
		}

		proc.Connections = connectionCounts[proc.PID]
		snapshot.Processes = append(snapshot.Processes, *proc)
		newProcesses[proc.PID] = proc

		// Update summary stats
		switch proc.Status {
		case "R", "running":
			running++
		case "S", "sleeping":
			sleeping++
		case "Z", "zombie":
			zombie++
		}
		cpuTotal += proc.CPUPercent
		memTotal += proc.MemoryMB
	}

	snapshot.Summary = models.ProcSummary{
		Total:    len(snapshot.Processes),
		Running:  running,
		Sleeping: sleeping,
		Zombie:   zombie,
		CPUTotal: cpuTotal,
		MemTotal: memTotal,
	}
	if err := ctx.Err(); err != nil {
		return err
	}

	s.mu.Lock()
	for pid, proc := range newProcesses {
		if _, exists := s.processes[pid]; !exists && s.OnProcess != nil {
			s.OnProcess(*proc)
		}
	}
	s.processes = newProcesses
	s.lastSnapshot = &snapshot

	// Keep limited history
	s.history = append(s.history, snapshot)
	if len(s.history) > 100 {
		s.history = s.history[1:]
	}
	s.mu.Unlock()

	s.mu.RLock()
	observer := s.observer
	s.mu.RUnlock()
	if observer != nil {
		observer(snapshot)
	}

	s.logger.Debug("process scan complete",
		zap.Int("total", snapshot.Summary.Total),
		zap.Int("running", snapshot.Summary.Running))

	return nil
}

// processInfo extracts information from a process
func (s *Service) processInfo(ctx context.Context, p *process.Process) *models.Process {
	name, err := p.NameWithContext(ctx)
	if err != nil {
		return nil
	}

	proc := &models.Process{
		PID:  p.Pid,
		Name: name,
	}

	// Get additional info (may fail for some processes)
	if ppid, err := p.PpidWithContext(ctx); err == nil {
		proc.PPID = ppid
	}

	if exe, err := p.ExeWithContext(ctx); err == nil {
		proc.Executable = exe
	}

	if cmdline, err := p.CmdlineWithContext(ctx); err == nil {
		proc.CommandLine = cmdline
	}

	if username, err := p.UsernameWithContext(ctx); err == nil {
		proc.Username = username
	}

	if status, err := p.StatusWithContext(ctx); err == nil && len(status) > 0 {
		proc.Status = status[0]
	}

	if createTime, err := p.CreateTimeWithContext(ctx); err == nil {
		proc.StartTime = time.UnixMilli(createTime)
	}

	if cpuPercent, err := p.CPUPercentWithContext(ctx); err == nil {
		proc.CPUPercent = cpuPercent
	}

	if memInfo, err := p.MemoryInfoWithContext(ctx); err == nil && memInfo != nil {
		proc.MemoryMB = float64(memInfo.RSS) / 1024 / 1024
	}

	return proc
}

// GetSnapshot returns the latest process snapshot
func (s *Service) GetSnapshot() *models.ProcessSnapshot {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.lastSnapshot
}

// GetProcess returns info for a specific PID
func (s *Service) GetProcess(pid int32) *models.Process {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.processes[pid]
}

// GetProcesses returns all current processes
func (s *Service) GetProcesses() []models.Process {
	s.mu.RLock()
	defer s.mu.RUnlock()

	procs := make([]models.Process, 0, len(s.processes))
	for _, p := range s.processes {
		procs = append(procs, *p)
	}
	return procs
}

// GetHistory returns historical snapshots
func (s *Service) GetHistory() []models.ProcessSnapshot {
	s.mu.RLock()
	defer s.mu.RUnlock()

	history := make([]models.ProcessSnapshot, len(s.history))
	copy(history, s.history)
	return history
}
