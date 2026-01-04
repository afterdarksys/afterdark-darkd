package process

import (
	"context"
	"os"
	"sync"
	"time"

	"github.com/afterdarksys/afterdark-darkd/internal/models"
	"github.com/afterdarksys/afterdark-darkd/internal/service"
	"github.com/afterdarksys/afterdark-darkd/pkg/logging"
	"github.com/shirou/gopsutil/v3/process"
	"go.uber.org/zap"
)

// Service monitors running processes
type Service struct {
	mu       sync.RWMutex
	config   *models.TrackingConfig
	running  bool
	cancel   context.CancelFunc
	logger   *zap.Logger

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

// Name returns the service identifier
func (s *Service) Name() string {
	return "process_tracker"
}

// Start initializes and starts the service
func (s *Service) Start(ctx context.Context) error {
	s.mu.Lock()
	if s.running {
		s.mu.Unlock()
		return nil
	}

	s.running = true
	ctx, s.cancel = context.WithCancel(ctx)
	s.mu.Unlock()

	s.logger.Info("starting process tracker service",
		zap.Duration("interval", s.config.ProcessInterval))

	// Initial scan
	if err := s.scan(); err != nil {
		s.logger.Warn("initial process scan failed", zap.Error(err))
	}

	// Start periodic scanning
	go s.runLoop(ctx)

	return nil
}

// Stop gracefully shuts down the service
func (s *Service) Stop(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.running {
		return nil
	}

	s.running = false
	if s.cancel != nil {
		s.cancel()
	}

	s.logger.Info("process tracker service stopped")
	return nil
}

// Health returns the current health status
func (s *Service) Health() service.HealthStatus {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if !s.running {
		return service.HealthStatus{
			Status:    service.HealthUnhealthy,
			Message:   "service not running",
			LastCheck: time.Now(),
		}
	}

	metrics := make(map[string]interface{})
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
	interval := s.config.ProcessInterval
	if interval == 0 {
		interval = 30 * time.Second
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := s.scan(); err != nil {
				s.logger.Warn("process scan failed", zap.Error(err))
			}
		}
	}
}

// scan collects current process information
func (s *Service) scan() error {
	procs, err := process.Processes()
	if err != nil {
		return err
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
		proc := s.processInfo(p)
		if proc == nil {
			continue
		}

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

	s.mu.Lock()
	s.processes = newProcesses
	s.lastSnapshot = &snapshot

	// Keep limited history
	s.history = append(s.history, snapshot)
	if len(s.history) > 100 {
		s.history = s.history[1:]
	}
	s.mu.Unlock()

	s.logger.Debug("process scan complete",
		zap.Int("total", snapshot.Summary.Total),
		zap.Int("running", snapshot.Summary.Running))

	return nil
}

// processInfo extracts information from a process
func (s *Service) processInfo(p *process.Process) *models.Process {
	name, err := p.Name()
	if err != nil {
		return nil
	}

	proc := &models.Process{
		PID:  p.Pid,
		Name: name,
	}

	// Get additional info (may fail for some processes)
	if ppid, err := p.Ppid(); err == nil {
		proc.PPID = ppid
	}

	if exe, err := p.Exe(); err == nil {
		proc.Executable = exe
	}

	if cmdline, err := p.Cmdline(); err == nil {
		proc.CommandLine = cmdline
	}

	if username, err := p.Username(); err == nil {
		proc.Username = username
	}

	if status, err := p.Status(); err == nil && len(status) > 0 {
		proc.Status = status[0]
	}

	if createTime, err := p.CreateTime(); err == nil {
		proc.StartTime = time.UnixMilli(createTime)
	}

	if cpuPercent, err := p.CPUPercent(); err == nil {
		proc.CPUPercent = cpuPercent
	}

	if memInfo, err := p.MemoryInfo(); err == nil && memInfo != nil {
		proc.MemoryMB = float64(memInfo.RSS) / 1024 / 1024
	}

	if conns, err := p.Connections(); err == nil {
		proc.Connections = len(conns)
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
