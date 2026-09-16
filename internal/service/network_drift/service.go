package network_drift

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/afterdarksys/afterdark-darkd/internal/events"
	"github.com/afterdarksys/afterdark-darkd/internal/service"
	gnet "github.com/shirou/gopsutil/v3/net"
)

const ServiceName = "network_drift"

type Config struct {
	Enabled      bool          `mapstructure:"enabled"`
	ScanInterval time.Duration `mapstructure:"scan_interval"`
}
type listener struct {
	Protocol, Address string
	Port              uint32
	PID               int32
}
type Service struct {
	config      Config
	registry    service.RegistryInterface
	mu          sync.RWMutex
	cancel      context.CancelFunc
	done        chan struct{}
	baseline    map[string]listener
	initialized bool
	lastScan    time.Time
	lastErr     error
	collect     func(context.Context) ([]gnet.ConnectionStat, error)
	emit        func(context.Context, listener) error
}

func New(config *Config, registry service.RegistryInterface) (*Service, error) {
	if config == nil {
		config = &Config{ScanInterval: time.Minute}
	}
	c := *config
	if c.ScanInterval <= 0 {
		return nil, fmt.Errorf("listener scan interval must be positive")
	}
	s := &Service{config: c, registry: registry, baseline: map[string]listener{}}
	s.collect = func(ctx context.Context) ([]gnet.ConnectionStat, error) {
		return gnet.ConnectionsWithContext(ctx, "tcp")
	}
	s.emit = func(ctx context.Context, l listener) error {
		exposure := "interface"
		if ip := net.ParseIP(l.Address); ip != nil {
			if ip.IsLoopback() {
				exposure = "loopback"
			} else if ip.IsUnspecified() {
				exposure = "wildcard"
			}
		}
		return events.Emit(registry, ServiceName, "network.listener_added", "warning", map[string]interface{}{
			"local_addr": l.Address, "local_port": l.Port, "pid": l.PID, "protocol": l.Protocol, "state": "LISTEN", "exposure": exposure,
			"facts": map[string]interface{}{"listening": true}, "collection_method": "polling", "reason": "TCP listener absent from previous successful snapshot; not proof of external reachability"})
	}
	return s, nil
}
func (s *Service) Name() string { return ServiceName }
func (s *Service) Start(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cancel != nil {
		return nil
	}
	ctx, s.cancel = context.WithCancel(ctx)
	s.done = make(chan struct{})
	s.initialized = false
	s.lastScan = time.Time{}
	s.lastErr = nil
	s.baseline = map[string]listener{}
	go func() {
		defer close(s.done)
		s.scan(ctx)
		ticker := time.NewTicker(s.config.ScanInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				s.scan(ctx)
			}
		}
	}()
	return nil
}
func (s *Service) Stop(ctx context.Context) error {
	s.mu.RLock()
	cancel, done := s.cancel, s.done
	s.mu.RUnlock()
	if cancel == nil {
		return nil
	}
	cancel()
	select {
	case <-done:
		s.mu.Lock()
		if s.done == done {
			s.cancel = nil
		}
		s.mu.Unlock()
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
func (s *Service) Configure(interface{}) error {
	return fmt.Errorf("listener configuration requires restart")
}
func (s *Service) Health() service.HealthStatus {
	s.mu.RLock()
	defer s.mu.RUnlock()
	status, message := service.HealthHealthy, "TCP listener snapshots active"
	if s.cancel == nil {
		status = service.HealthUnknown
		message = "listener observer stopped"
	} else if s.lastErr != nil {
		status = service.HealthDegraded
		message = s.lastErr.Error()
	} else if s.lastScan.IsZero() {
		status = service.HealthUnknown
		message = "waiting for first listener snapshot"
	}
	return service.HealthStatus{Status: status, Message: message, LastCheck: time.Now(), Metrics: map[string]interface{}{"last_scan": s.lastScan, "listeners": len(s.baseline), "scope": "TCP polling; process start identity and UDP coverage unavailable"}}
}
func (s *Service) scan(ctx context.Context) {
	snapshot, err := s.collect(ctx)
	fail := func(err error) { s.mu.Lock(); s.lastErr = err; s.mu.Unlock() }
	if err != nil {
		fail(err)
		return
	}
	if len(snapshot) > 50000 {
		fail(fmt.Errorf("connection snapshot exceeds 50000 records; baseline retained"))
		return
	}
	s.mu.RLock()
	previous, initialized := s.baseline, s.initialized
	s.mu.RUnlock()
	next := map[string]listener{}
	for _, c := range snapshot {
		if c.Status != "LISTEN" {
			continue
		}
		l := listener{Protocol: "tcp", Address: c.Laddr.IP, Port: c.Laddr.Port, PID: c.Pid}
		next[fmt.Sprintf("%s:%d/%d", l.Address, l.Port, l.PID)] = l
	}
	if initialized {
		for key, l := range next {
			if err := ctx.Err(); err != nil {
				fail(err)
				return
			}
			if _, exists := previous[key]; !exists {
				if err = s.emit(ctx, l); err != nil {
					fail(err)
					return
				}
			}
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.baseline = next
	s.initialized = true
	s.lastErr = nil
	s.lastScan = time.Now().UTC()
}
