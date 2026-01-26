package svcmon

import (
	"bufio"
	"context"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/afterdarksys/afterdark-darkd/internal/models"
	"github.com/afterdarksys/afterdark-darkd/internal/service"
	"github.com/afterdarksys/afterdark-darkd/pkg/logging"
	"go.uber.org/zap"
)

// Service monitors system services/daemons
type Service struct {
	mu      sync.RWMutex
	config  *models.TrackingConfig
	running bool
	cancel  context.CancelFunc
	logger  *zap.Logger

	// Current services
	services map[string]*models.SystemService

	// Change history
	changes []ServiceChange
}

// ServiceChange represents a service state change
type ServiceChange struct {
	Timestamp   time.Time `json:"timestamp"`
	ServiceName string    `json:"service_name"`
	OldStatus   string    `json:"old_status"`
	NewStatus   string    `json:"new_status"`
}

// New creates a new service monitor
func New(config *models.TrackingConfig) *Service {
	return &Service{
		config:   config,
		services: make(map[string]*models.SystemService),
		changes:  make([]ServiceChange, 0),
		logger:   logging.Get().Named("svcmon"),
	}
}

// Name returns the service identifier
func (s *Service) Name() string {
	return "service_monitor"
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

	s.logger.Info("starting service monitor",
		zap.Duration("interval", s.config.ServiceInterval))

	// Initial scan
	if err := s.scan(); err != nil {
		s.logger.Warn("initial service scan failed", zap.Error(err))
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

	s.logger.Info("service monitor stopped")
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

	return service.HealthStatus{
		Status:    service.HealthHealthy,
		Message:   "service monitoring active",
		LastCheck: time.Now(),
		Metrics: map[string]interface{}{
			"services_tracked": len(s.services),
		},
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

// runLoop runs the periodic service scan
func (s *Service) runLoop(ctx context.Context) {
	interval := s.config.ServiceInterval
	if interval == 0 {
		interval = 60 * time.Second
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := s.scan(); err != nil {
				s.logger.Warn("service scan failed", zap.Error(err))
			}
		}
	}
}

// scan collects current service information
func (s *Service) scan() error {
	var services []models.SystemService
	var err error

	switch runtime.GOOS {
	case "darwin":
		services, err = s.scanDarwin()
	case "linux":
		services, err = s.scanLinux()
	case "windows":
		services, err = s.scanWindows()
	default:
		s.logger.Warn("unsupported platform for service monitoring", zap.String("os", runtime.GOOS))
		return nil
	}

	if err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	// Detect changes
	newServices := make(map[string]*models.SystemService)
	for i := range services {
		svc := &services[i]
		newServices[svc.Name] = svc

		if old, exists := s.services[svc.Name]; exists {
			if old.Status != svc.Status {
				s.changes = append(s.changes, ServiceChange{
					Timestamp:   time.Now(),
					ServiceName: svc.Name,
					OldStatus:   old.Status,
					NewStatus:   svc.Status,
				})
				s.logger.Info("service status changed",
					zap.String("service", svc.Name),
					zap.String("old", old.Status),
					zap.String("new", svc.Status))
			}
		}
	}

	s.services = newServices

	// Keep limited history
	if len(s.changes) > 500 {
		s.changes = s.changes[100:]
	}

	s.logger.Debug("service scan complete", zap.Int("services", len(s.services)))
	return nil
}

// scanDarwin scans services on macOS
// On darwin builds, this tries native plist parsing first via scanDarwinNative()
// (defined in service_darwin.go). On other platforms, this is a no-op stub.
func (s *Service) scanDarwin() ([]models.SystemService, error) {
	// This will be overridden by service_darwin.go on darwin builds
	// For non-darwin builds, fall back to launchctl (which won't work anyway)
	return s.scanDarwinLaunchctl()
}

// scanDarwinLaunchctl uses launchctl as fallback (requires exec.Command)
func (s *Service) scanDarwinLaunchctl() ([]models.SystemService, error) {
	services := make([]models.SystemService, 0)

	// List system services
	cmd := exec.Command("launchctl", "list")
	output, err := cmd.Output()
	if err != nil {
		return services, err
	}

	scanner := bufio.NewScanner(strings.NewReader(string(output)))
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		if lineNum == 1 {
			continue // Skip header
		}

		line := scanner.Text()
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}

		pid := fields[0]
		name := fields[2]

		status := "stopped"
		if pid != "-" {
			status = "running"
		}

		services = append(services, models.SystemService{
			Name:   name,
			Status: status,
		})
	}

	return services, nil
}

// scanLinux scans services on Linux using systemctl
func (s *Service) scanLinux() ([]models.SystemService, error) {
	services := make([]models.SystemService, 0)

	// List all services
	cmd := exec.Command("systemctl", "list-units", "--type=service", "--all", "--no-pager", "--plain")
	output, err := cmd.Output()
	if err != nil {
		// Fallback to service command
		return s.scanLinuxFallback()
	}

	scanner := bufio.NewScanner(strings.NewReader(string(output)))
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.Contains(line, ".service") {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}

		name := strings.TrimSuffix(fields[0], ".service")
		status := "stopped"
		if fields[2] == "active" {
			status = "running"
		}

		services = append(services, models.SystemService{
			Name:   name,
			Status: status,
		})
	}

	return services, nil
}

// scanLinuxFallback uses older service command
func (s *Service) scanLinuxFallback() ([]models.SystemService, error) {
	services := make([]models.SystemService, 0)

	cmd := exec.Command("service", "--status-all")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return services, nil // Just return empty on error
	}

	scanner := bufio.NewScanner(strings.NewReader(string(output)))
	for scanner.Scan() {
		line := scanner.Text()
		// Format: [ + ] service_name or [ - ] service_name
		if len(line) < 5 {
			continue
		}

		status := "stopped"
		if strings.Contains(line, "[ + ]") {
			status = "running"
		}

		// Extract service name
		parts := strings.Fields(line)
		if len(parts) >= 4 {
			name := parts[3]
			services = append(services, models.SystemService{
				Name:   name,
				Status: status,
			})
		}
	}

	return services, nil
}

// scanWindows scans services on Windows
func (s *Service) scanWindows() ([]models.SystemService, error) {
	services := make([]models.SystemService, 0)

	// Use PowerShell to get services
	cmd := exec.Command("powershell", "-Command", "Get-Service | Select-Object Name, DisplayName, Status | ConvertTo-Csv -NoTypeInformation")
	output, err := cmd.Output()
	if err != nil {
		return services, err
	}

	scanner := bufio.NewScanner(strings.NewReader(string(output)))
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		if lineNum == 1 {
			continue // Skip header
		}

		line := scanner.Text()
		// Parse CSV: "Name","DisplayName","Status"
		parts := strings.Split(line, ",")
		if len(parts) < 3 {
			continue
		}

		name := strings.Trim(parts[0], "\"")
		displayName := strings.Trim(parts[1], "\"")
		status := strings.ToLower(strings.Trim(parts[2], "\""))

		services = append(services, models.SystemService{
			Name:        name,
			DisplayName: displayName,
			Status:      status,
		})
	}

	return services, nil
}

// GetServices returns all tracked services
func (s *Service) GetServices() []models.SystemService {
	s.mu.RLock()
	defer s.mu.RUnlock()

	svcs := make([]models.SystemService, 0, len(s.services))
	for _, svc := range s.services {
		svcs = append(svcs, *svc)
	}
	return svcs
}

// GetService returns a specific service by name
func (s *Service) GetService(name string) *models.SystemService {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.services[name]
}

// GetRunningServices returns only running services
func (s *Service) GetRunningServices() []models.SystemService {
	s.mu.RLock()
	defer s.mu.RUnlock()

	running := make([]models.SystemService, 0)
	for _, svc := range s.services {
		if svc.Status == "running" {
			running = append(running, *svc)
		}
	}
	return running
}

// GetChanges returns recent service changes
func (s *Service) GetChanges(limit int) []ServiceChange {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if limit <= 0 || limit > len(s.changes) {
		limit = len(s.changes)
	}

	start := len(s.changes) - limit
	changes := make([]ServiceChange, limit)
	copy(changes, s.changes[start:])

	return changes
}
