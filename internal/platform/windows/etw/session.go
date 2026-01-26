//go:build windows

package etw

import (
	"fmt"
	"sync"
	"time"

	"github.com/0xrawsec/golang-etw/etw"
	"go.uber.org/zap"
)

// Session manages an ETW trace session
type Session struct {
	Name    string
	Session *etw.Session
	logger  *zap.Logger
	mu      sync.Mutex
	running bool
}

// NewSession creates a new ETW session
func NewSession(name string, logger *zap.Logger) *Session {
	return &Session{
		Name:   name,
		logger: logger,
	}
}

// Start starts the ETW session
func (s *Session) Start() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.running {
		return nil
	}

	// Create real-time session
	session, err := etw.NewRealTimeSession(s.Name)
	if err != nil {
		return fmt.Errorf("failed to create ETW session: %w", err)
	}
	s.Session = session

	// Subscribe to "Microsoft-Windows-Kernel-Process"
	// Provider GUID: {22fb2cd6-0e7b-422b-a0c7-2fad1fd0e716}
	if err := s.Session.EnableProvider(etw.MustParseProviderGUID("{22fb2cd6-0e7b-422b-a0c7-2fad1fd0e716}")); err != nil {
		s.Session.Stop()
		return fmt.Errorf("failed to enable kernel process provider: %w", err)
	}

	// Subscribe to "Microsoft-Windows-DNS-Client"
	// Provider GUID: {1C95126E-7EEA-49A9-A3FE-A378B03DDB4D}
	if err := s.Session.EnableProvider(etw.MustParseProviderGUID("{1C95126E-7EEA-49A9-A3FE-A378B03DDB4D}")); err != nil {
		s.logger.Warn("failed to enable DNS provider", zap.Error(err))
		// Don't fail completely just for DNS
	}

	s.running = true

	// Start processing loop in background
	go s.processLoop()

	return nil
}

// Stop stops the ETW session
func (s *Session) Stop() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.running || s.Session == nil {
		return nil
	}

	if err := s.Session.Stop(); err != nil {
		return err
	}

	s.running = false
	return nil
}

func (s *Session) processLoop() {
	c := etw.NewRealTimeConsumer(s.logger) // Assuming a wrapper function or using the library's consumer
	defer c.Stop()

	// Connect consumer to session
	// Note: Actual library usage might differ slightly based on version, simplified here
	// In reality, we traverse events from s.Session.Events() channel if available, or use a callback

	// Stub implementation for compilation check
	for s.running {
		time.Sleep(1 * time.Second)
	}
}
