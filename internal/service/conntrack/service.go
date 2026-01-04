package conntrack

import (
	"context"
	"fmt"
	"net"
	"os"
	"sort"
	"sync"
	"time"

	"github.com/afterdarksys/afterdark-darkd/internal/models"
	"github.com/afterdarksys/afterdark-darkd/internal/service"
	"github.com/afterdarksys/afterdark-darkd/pkg/logging"
	gopsnet "github.com/shirou/gopsutil/v3/net"
	"github.com/shirou/gopsutil/v3/process"
	"go.uber.org/zap"
)

// Service tracks network connections over time
type Service struct {
	mu       sync.RWMutex
	config   *models.TrackingConfig
	running  bool
	cancel   context.CancelFunc
	logger   *zap.Logger

	// Current connections
	activeConns map[string]*models.NetworkConnection

	// Tracked connections with history
	trackedConns map[string]*models.TrackedConnection

	// Connection events
	events []models.ConnectionEvent

	// Statistics
	lastSummary *models.ConnectionSummary
}

// New creates a new connection tracking service
func New(config *models.TrackingConfig) *Service {
	return &Service{
		config:       config,
		activeConns:  make(map[string]*models.NetworkConnection),
		trackedConns: make(map[string]*models.TrackedConnection),
		events:       make([]models.ConnectionEvent, 0),
		logger:       logging.Get().Named("conntrack"),
	}
}

// Name returns the service identifier
func (s *Service) Name() string {
	return "connection_tracker"
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

	s.logger.Info("starting connection tracker service",
		zap.Duration("interval", s.config.NetworkInterval))

	// Initial scan
	if err := s.scan(); err != nil {
		s.logger.Warn("initial connection scan failed", zap.Error(err))
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

	s.logger.Info("connection tracker service stopped")
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
	metrics["active_connections"] = len(s.activeConns)
	metrics["tracked_connections"] = len(s.trackedConns)
	if s.lastSummary != nil {
		metrics["last_scan"] = s.lastSummary.Timestamp
	}

	return service.HealthStatus{
		Status:    service.HealthHealthy,
		Message:   "connection tracking active",
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

// runLoop runs the periodic connection scan
func (s *Service) runLoop(ctx context.Context) {
	interval := s.config.NetworkInterval
	if interval == 0 {
		interval = 10 * time.Second
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := s.scan(); err != nil {
				s.logger.Warn("connection scan failed", zap.Error(err))
			}
		}
	}
}

// scan collects current network connections
func (s *Service) scan() error {
	conns, err := gopsnet.Connections("all")
	if err != nil {
		return err
	}

	now := time.Now()
	newActive := make(map[string]*models.NetworkConnection)

	var established, listening, timeWait int
	uniqueIPs := make(map[string]struct{})
	uniqueProcs := make(map[int32]struct{})
	procConnCount := make(map[int32]int)

	for _, c := range conns {
		// Skip connections without remote address (unless listening)
		if c.Raddr.IP == "" && c.Status != "LISTEN" {
			continue
		}

		// Skip local connections if configured
		if !s.config.TrackLocalConns && isLocalIP(c.Raddr.IP) {
			continue
		}

		conn := s.connectionFromGopsutil(c, now)
		key := s.connectionKey(conn)

		newActive[key] = conn

		// Track unique IPs and processes
		if conn.RemoteAddr != "" {
			uniqueIPs[conn.RemoteAddr] = struct{}{}
		}
		if conn.PID > 0 {
			uniqueProcs[conn.PID] = struct{}{}
			procConnCount[conn.PID]++
		}

		// Update stats
		switch conn.State {
		case "ESTABLISHED":
			established++
		case "LISTEN":
			listening++
		case "TIME_WAIT":
			timeWait++
		}

		// Update tracked connection
		s.updateTracked(key, conn, now)
	}

	// Detect closed connections
	s.mu.Lock()
	for key, oldConn := range s.activeConns {
		if _, exists := newActive[key]; !exists {
			// Connection closed
			s.addEvent("closed", oldConn)
		}
	}

	// Detect new connections
	for key, newConn := range newActive {
		if _, exists := s.activeConns[key]; !exists {
			// New connection
			s.addEvent("new", newConn)
		}
	}

	s.activeConns = newActive

	// Build summary
	s.lastSummary = &models.ConnectionSummary{
		Timestamp:       now,
		TotalActive:     len(newActive),
		Established:     established,
		Listening:       listening,
		TimeWait:        timeWait,
		UniqueRemoteIPs: len(uniqueIPs),
		UniqueProcesses: len(uniqueProcs),
		TopDestinations: s.getTopDestinations(10),
		TopProcesses:    s.getTopProcesses(procConnCount, 10),
	}

	s.mu.Unlock()

	s.logger.Debug("connection scan complete",
		zap.Int("active", len(newActive)),
		zap.Int("established", established),
		zap.Int("tracked", len(s.trackedConns)))

	return nil
}

// connectionFromGopsutil converts gopsutil connection to our model
func (s *Service) connectionFromGopsutil(c gopsnet.ConnectionStat, now time.Time) *models.NetworkConnection {
	conn := &models.NetworkConnection{
		Protocol:   protocolName(c.Type),
		LocalAddr:  c.Laddr.IP,
		LocalPort:  uint16(c.Laddr.Port),
		RemoteAddr: c.Raddr.IP,
		RemotePort: uint16(c.Raddr.Port),
		State:      c.Status,
		PID:        c.Pid,
		FirstSeen:  now,
		LastSeen:   now,
	}

	// Get process name
	if c.Pid > 0 {
		if p, err := process.NewProcess(c.Pid); err == nil {
			if name, err := p.Name(); err == nil {
				conn.ProcessName = name
			}
			if username, err := p.Username(); err == nil {
				conn.Username = username
			}
		}
	}

	return conn
}

// connectionKey generates a unique key for a connection
func (s *Service) connectionKey(c *models.NetworkConnection) string {
	return fmt.Sprintf("%s:%s:%d:%s:%d",
		c.Protocol, c.LocalAddr, c.LocalPort, c.RemoteAddr, c.RemotePort)
}

// updateTracked updates or creates a tracked connection
func (s *Service) updateTracked(key string, conn *models.NetworkConnection, now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if tracked, exists := s.trackedConns[key]; exists {
		// Update existing
		duration := now.Sub(tracked.LastSeen).Seconds()
		tracked.LastSeen = now
		tracked.TotalDuration += duration
		tracked.Occurrences++
		tracked.ProcessName = conn.ProcessName
		tracked.PID = conn.PID
	} else {
		// Create new tracked connection
		s.trackedConns[key] = &models.TrackedConnection{
			Key: models.ConnectionKey{
				Protocol:   conn.Protocol,
				LocalAddr:  conn.LocalAddr,
				LocalPort:  conn.LocalPort,
				RemoteAddr: conn.RemoteAddr,
				RemotePort: conn.RemotePort,
			},
			FirstSeen:     now,
			LastSeen:      now,
			Occurrences:   1,
			TotalDuration: 0,
			ProcessName:   conn.ProcessName,
			PID:           conn.PID,
		}

		// Optionally resolve hostname
		if s.config.ResolveHostnames && conn.RemoteAddr != "" {
			go s.resolveHostname(key, conn.RemoteAddr)
		}
	}
}

// resolveHostname resolves the hostname for an IP address
func (s *Service) resolveHostname(key, ip string) {
	names, err := net.LookupAddr(ip)
	if err != nil || len(names) == 0 {
		return
	}

	s.mu.Lock()
	if tracked, exists := s.trackedConns[key]; exists {
		tracked.RemoteHostname = names[0]
	}
	s.mu.Unlock()
}

// addEvent adds a connection event to history
func (s *Service) addEvent(eventType string, conn *models.NetworkConnection) {
	event := models.ConnectionEvent{
		Timestamp:  time.Now(),
		EventType:  eventType,
		Connection: *conn,
	}

	s.events = append(s.events, event)

	// Keep limited event history
	if len(s.events) > 1000 {
		s.events = s.events[100:]
	}
}

// getTopDestinations returns top N destinations by connection count
func (s *Service) getTopDestinations(n int) []models.DestinationStat {
	destStats := make(map[string]*models.DestinationStat)

	for _, tracked := range s.trackedConns {
		key := fmt.Sprintf("%s:%d:%s", tracked.Key.RemoteAddr, tracked.Key.RemotePort, tracked.Key.Protocol)
		if stat, exists := destStats[key]; exists {
			stat.Connections++
			stat.TotalDuration += tracked.TotalDuration
			stat.Occurrences += tracked.Occurrences
		} else {
			destStats[key] = &models.DestinationStat{
				RemoteAddr:     tracked.Key.RemoteAddr,
				RemoteHostname: tracked.RemoteHostname,
				RemotePort:     tracked.Key.RemotePort,
				Protocol:       tracked.Key.Protocol,
				Connections:    1,
				TotalDuration:  tracked.TotalDuration,
				Occurrences:    tracked.Occurrences,
				ThreatScore:    tracked.ThreatScore,
			}
		}
	}

	// Convert to slice and sort
	stats := make([]models.DestinationStat, 0, len(destStats))
	for _, stat := range destStats {
		stats = append(stats, *stat)
	}

	sort.Slice(stats, func(i, j int) bool {
		return stats[i].Occurrences > stats[j].Occurrences
	})

	if len(stats) > n {
		stats = stats[:n]
	}

	return stats
}

// getTopProcesses returns top N processes by connection count
func (s *Service) getTopProcesses(counts map[int32]int, n int) []models.ProcessConnStat {
	// Get unique IPs per process
	procIPs := make(map[int32]map[string]struct{})
	for _, tracked := range s.trackedConns {
		if _, exists := procIPs[tracked.PID]; !exists {
			procIPs[tracked.PID] = make(map[string]struct{})
		}
		procIPs[tracked.PID][tracked.Key.RemoteAddr] = struct{}{}
	}

	// Build stats
	stats := make([]models.ProcessConnStat, 0, len(counts))
	for pid, count := range counts {
		var procName string
		if p, err := process.NewProcess(pid); err == nil {
			if name, err := p.Name(); err == nil {
				procName = name
			}
		}

		uniqueIPs := 0
		if ips, exists := procIPs[pid]; exists {
			uniqueIPs = len(ips)
		}

		stats = append(stats, models.ProcessConnStat{
			ProcessName:     procName,
			PID:             pid,
			ActiveConns:     count,
			UniqueRemoteIPs: uniqueIPs,
		})
	}

	sort.Slice(stats, func(i, j int) bool {
		return stats[i].ActiveConns > stats[j].ActiveConns
	})

	if len(stats) > n {
		stats = stats[:n]
	}

	return stats
}

// GetActiveConnections returns current active connections
func (s *Service) GetActiveConnections() []models.NetworkConnection {
	s.mu.RLock()
	defer s.mu.RUnlock()

	conns := make([]models.NetworkConnection, 0, len(s.activeConns))
	for _, c := range s.activeConns {
		conns = append(conns, *c)
	}
	return conns
}

// GetTrackedConnections returns all tracked connections with history
func (s *Service) GetTrackedConnections() []models.TrackedConnection {
	s.mu.RLock()
	defer s.mu.RUnlock()

	tracked := make([]models.TrackedConnection, 0, len(s.trackedConns))
	for _, t := range s.trackedConns {
		tracked = append(tracked, *t)
	}

	// Sort by occurrences
	sort.Slice(tracked, func(i, j int) bool {
		return tracked[i].Occurrences > tracked[j].Occurrences
	})

	return tracked
}

// GetSummary returns the latest connection summary
func (s *Service) GetSummary() *models.ConnectionSummary {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.lastSummary
}

// GetEvents returns recent connection events
func (s *Service) GetEvents(limit int) []models.ConnectionEvent {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if limit <= 0 || limit > len(s.events) {
		limit = len(s.events)
	}

	// Return most recent events
	start := len(s.events) - limit
	events := make([]models.ConnectionEvent, limit)
	copy(events, s.events[start:])

	return events
}

// GetConnectionsByProcess returns connections for a specific process
func (s *Service) GetConnectionsByProcess(pid int32) []models.NetworkConnection {
	s.mu.RLock()
	defer s.mu.RUnlock()

	conns := make([]models.NetworkConnection, 0)
	for _, c := range s.activeConns {
		if c.PID == pid {
			conns = append(conns, *c)
		}
	}
	return conns
}

// GetConnectionsByRemote returns connections to a specific remote IP
func (s *Service) GetConnectionsByRemote(ip string) []models.TrackedConnection {
	s.mu.RLock()
	defer s.mu.RUnlock()

	tracked := make([]models.TrackedConnection, 0)
	for _, t := range s.trackedConns {
		if t.Key.RemoteAddr == ip {
			tracked = append(tracked, *t)
		}
	}
	return tracked
}

// FlagConnection marks a connection as suspicious
func (s *Service) FlagConnection(key string, threatScore int, category string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if tracked, exists := s.trackedConns[key]; exists {
		tracked.ThreatScore = threatScore
		tracked.ThreatCategory = category
		tracked.Flagged = true

		// Add flagged event
		if conn, ok := s.activeConns[key]; ok {
			s.events = append(s.events, models.ConnectionEvent{
				Timestamp:  time.Now(),
				EventType:  "flagged",
				Connection: *conn,
				Details:    fmt.Sprintf("Threat: %s (score: %d)", category, threatScore),
			})
		}
	}
}

// GetFlaggedConnections returns all flagged connections
func (s *Service) GetFlaggedConnections() []models.TrackedConnection {
	s.mu.RLock()
	defer s.mu.RUnlock()

	flagged := make([]models.TrackedConnection, 0)
	for _, t := range s.trackedConns {
		if t.Flagged {
			flagged = append(flagged, *t)
		}
	}

	// Sort by threat score
	sort.Slice(flagged, func(i, j int) bool {
		return flagged[i].ThreatScore > flagged[j].ThreatScore
	})

	return flagged
}

// ExportForAPI returns connection data formatted for API submission
func (s *Service) ExportForAPI() map[string]interface{} {
	s.mu.RLock()
	defer s.mu.RUnlock()

	hostname, _ := os.Hostname()

	return map[string]interface{}{
		"hostname":    hostname,
		"timestamp":   time.Now(),
		"summary":     s.lastSummary,
		"connections": s.GetTrackedConnections(),
		"flagged":     s.GetFlaggedConnections(),
	}
}

// Helper functions

func protocolName(t uint32) string {
	switch t {
	case 1:
		return "tcp"
	case 2:
		return "udp"
	case 3:
		return "tcp6"
	case 4:
		return "udp6"
	default:
		return fmt.Sprintf("proto-%d", t)
	}
}

func isLocalIP(ip string) bool {
	if ip == "" || ip == "127.0.0.1" || ip == "::1" {
		return true
	}

	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}

	// Check RFC1918 private ranges
	privateRanges := []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"fc00::/7", // IPv6 private
	}

	for _, cidr := range privateRanges {
		_, network, _ := net.ParseCIDR(cidr)
		if network.Contains(parsed) {
			return true
		}
	}

	return false
}
