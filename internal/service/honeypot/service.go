package honeypot

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/afterdarksys/afterdark-darkd/internal/service"
	"github.com/afterdarksys/afterdark-darkd/pkg/logging"
	"go.uber.org/zap"
)

const ServiceName = "honeypot"

type Config struct {
	Enabled bool  `mapstructure:"enabled"`
	Ports   []int `mapstructure:"ports"` // Ports to listen on (e.g., 2323, 33890)
}

type Service struct {
	config   *Config
	logger   *zap.Logger
	registry service.RegistryInterface

	listeners []net.Listener
	mu        sync.RWMutex
	running   bool
	stopCh    chan struct{}
}

func New(config *Config, registry service.RegistryInterface) (*Service, error) {
	if config == nil {
		config = &Config{
			Enabled: true,
			Ports:   []int{2323, 2222, 33890},
		}
	}

	return &Service{
		config:   config,
		logger:   logging.With(zap.String("service", ServiceName)),
		registry: registry,
		stopCh:   make(chan struct{}),
	}, nil
}

func (s *Service) Name() string {
	return ServiceName
}

func (s *Service) Start(ctx context.Context) error {
	s.mu.Lock()
	if s.running {
		s.mu.Unlock()
		return nil
	}
	s.running = true
	s.mu.Unlock()

	s.logger.Info("starting honeypot service", zap.Ints("ports", s.config.Ports))

	for _, port := range s.config.Ports {
		go s.startListener(port)
	}

	return nil
}

func (s *Service) Stop(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.running {
		return nil
	}
	s.running = false
	close(s.stopCh)

	for _, l := range s.listeners {
		l.Close()
	}
	s.listeners = nil
	s.logger.Info("stopped honeypot service")
	return nil
}

func (s *Service) Configure(config interface{}) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if cfg, ok := config.(*Config); ok {
		s.config = cfg
	}
	// Note: Dynamic port update requires restart in this simple impl
	return nil
}

func (s *Service) Health() service.HealthStatus {
	s.mu.RLock()
	defer s.mu.RUnlock()

	status := service.HealthHealthy
	msg := fmt.Sprintf("listening on %d ports", len(s.listeners))

	if s.running && len(s.listeners) == 0 && len(s.config.Ports) > 0 {
		status = service.HealthDegraded
		msg = "no active listeners"
	}

	return service.HealthStatus{
		Status:    status,
		Message:   msg,
		LastCheck: time.Now(),
	}
}

func (s *Service) startListener(port int) {
	addr := fmt.Sprintf(":%d", port)
	l, err := net.Listen("tcp", addr)
	if err != nil {
		s.logger.Error("failed to start honeypot listener", zap.Int("port", port), zap.Error(err))
		return
	}

	s.mu.Lock()
	s.listeners = append(s.listeners, l)
	s.mu.Unlock()

	s.logger.Info("honeypot listener active", zap.Int("port", port))

	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				// check if stopped
				s.mu.RLock()
				running := s.running
				s.mu.RUnlock()
				if !running {
					return
				}
				s.logger.Error("accept error", zap.Error(err))
				return
			}

			s.handleConnection(conn, port)
		}
	}()
}

func (s *Service) handleConnection(conn net.Conn, port int) {
	defer conn.Close()

	remote := conn.RemoteAddr().String()
	s.logger.Warn("HONEYPOT ALERT: Connection attempt detected",
		zap.String("remote_addr", remote),
		zap.Int("target_port", port))

	// Fake banner
	conn.Write([]byte("SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5\r\n"))
	time.Sleep(1 * time.Second)
}
