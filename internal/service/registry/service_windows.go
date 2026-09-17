//go:build windows

package registry

import (
	"context"
	"crypto/sha256"
	"fmt"
	"github.com/afterdarksys/afterdark-darkd/internal/events"
	"github.com/afterdarksys/afterdark-darkd/internal/service"
	winreg "golang.org/x/sys/windows/registry"
	"sync"
	"time"
)

const ServiceName = "registry_monitor"

type Config struct {
	Enabled  bool          `mapstructure:"enabled"`
	Interval time.Duration `mapstructure:"interval"`
}
type Service struct {
	mu       sync.Mutex
	config   Config
	registry service.RegistryInterface
	cancel   context.CancelFunc
	done     chan struct{}
	lastErr  error
	previous map[string]string
}

func New(config *Config, registry service.RegistryInterface) (*Service, error) {
	if config == nil {
		config = &Config{Interval: 30 * time.Second}
	}
	if config.Interval <= 0 {
		config.Interval = 30 * time.Second
	}
	return &Service{config: *config, registry: registry}, nil
}
func (s *Service) Name() string { return ServiceName }
func (s *Service) Configure(interface{}) error {
	return fmt.Errorf("registry configuration requires restart")
}
func (s *Service) Start(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cancel != nil {
		return nil
	}
	baseline, err := snapshot()
	if err != nil {
		return err
	}
	s.previous = baseline
	ctx, s.cancel = context.WithCancel(ctx)
	s.done = make(chan struct{})
	go s.run(ctx)
	return nil
}
func (s *Service) Stop(ctx context.Context) error {
	s.mu.Lock()
	cancel, done := s.cancel, s.done
	s.mu.Unlock()
	if cancel == nil {
		return nil
	}
	cancel()
	select {
	case <-done:
		s.mu.Lock()
		s.cancel = nil
		s.mu.Unlock()
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
func (s *Service) Health() service.HealthStatus {
	s.mu.Lock()
	defer s.mu.Unlock()
	h := service.HealthStatus{Status: service.HealthHealthy, Message: "registry persistence polling active", LastCheck: time.Now()}
	if s.cancel == nil {
		h.Status = service.HealthUnhealthy
		h.Message = "stopped"
	} else if s.lastErr != nil {
		h.Status = service.HealthDegraded
		h.Message = s.lastErr.Error()
	}
	return h
}
func (s *Service) run(ctx context.Context) {
	defer close(s.done)
	ticker := time.NewTicker(s.config.Interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			current, err := snapshot()
			if err == nil {
				for _, change := range changes(s.previous, current) {
					if err = events.Emit(s.registry, ServiceName, "registry_persistence_changed", "high", change); err != nil {
						break
					}
				}
				if err == nil {
					s.previous = current
				}
			}
			s.mu.Lock()
			s.lastErr = err
			s.mu.Unlock()
		}
	}
}
func snapshot() (map[string]string, error) {
	result := map[string]string{}
	for _, hive := range []struct {
		name string
		key  winreg.Key
	}{{"HKLM", winreg.LOCAL_MACHINE}, {"HKCU", winreg.CURRENT_USER}} {
		for _, view := range []uint32{winreg.WOW64_64KEY, winreg.WOW64_32KEY} {
			for _, path := range []string{`SOFTWARE\Microsoft\Windows\CurrentVersion\Run`, `SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce`} {
				key, err := winreg.OpenKey(hive.key, path, winreg.QUERY_VALUE|view)
				if err == winreg.ErrNotExist {
					continue
				}
				if err != nil {
					return nil, err
				}
				values, err := key.ReadValueNames(0)
				if err != nil {
					key.Close()
					return nil, err
				}
				for _, name := range values {
					n, kind, err := key.GetValue(name, nil)
					if err != nil {
						key.Close()
						return nil, err
					}
					if n > 1<<20 {
						key.Close()
						return nil, fmt.Errorf("registry value exceeds 1 MiB")
					}
					data := make([]byte, n)
					n, _, err = key.GetValue(name, data)
					if err != nil {
						key.Close()
						return nil, err
					}
					digest := sha256.Sum256(data[:n])
					result[fmt.Sprintf("%s:%d:%s:%s", hive.name, view, path, name)] = fmt.Sprintf("%d:%x", kind, digest)
				}
				key.Close()
			}
		}
	}
	return result, nil
}
