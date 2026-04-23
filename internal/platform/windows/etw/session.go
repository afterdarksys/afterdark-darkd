//go:build windows

package etw

import (
	"context"
	"fmt"
	"sync"

	"github.com/0xrawsec/golang-etw/etw"
	"go.uber.org/zap"
)

// Session manages an ETW trace session
type Session struct {
	Name    string
	Session *etw.RealTimeSession
	logger  *zap.Logger
	mu      sync.Mutex
	cancel  context.CancelFunc
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

	// Create real-time session (no error return)
	session := etw.NewRealTimeSession(s.Name)

	// Subscribe to "Microsoft-Windows-Kernel-Process"
	// Provider GUID: {22fb2cd6-0e7b-422b-a0c7-2fad1fd0e716}
	kernelProc := etw.MustParseProvider("{22fb2cd6-0e7b-422b-a0c7-2fad1fd0e716}")
	if err := session.EnableProvider(kernelProc); err != nil {
		_ = session.Stop()
		return fmt.Errorf("failed to enable kernel process provider: %w", err)
	}

	// Subscribe to "Microsoft-Windows-DNS-Client"
	// Provider GUID: {1C95126E-7EEA-49A9-A3FE-A378B03DDB4D}
	dnsClient := etw.MustParseProvider("{1C95126E-7EEA-49A9-A3FE-A378B03DDB4D}")
	if err := session.EnableProvider(dnsClient); err != nil {
		s.logger.Warn("failed to enable DNS provider", zap.Error(err))
		// Don't fail completely just for DNS
	}

	s.Session = session
	s.running = true

	ctx, cancel := context.WithCancel(context.Background())
	s.cancel = cancel

	// Start processing loop in background
	go s.processLoop(ctx)

	return nil
}

// Stop stops the ETW session
func (s *Session) Stop() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.running || s.Session == nil {
		return nil
	}

	if s.cancel != nil {
		s.cancel()
	}

	if err := s.Session.Stop(); err != nil {
		return err
	}

	s.running = false
	return nil
}

func (s *Session) processLoop(ctx context.Context) {
	consumer := etw.NewRealTimeConsumer(ctx).FromSessions(s.Session)
	defer consumer.Stop()

	if err := consumer.Start(); err != nil {
		s.logger.Error("ETW consumer failed to start", zap.Error(err))
		return
	}

	for {
		select {
		case <-ctx.Done():
			return
		case event, ok := <-consumer.Events:
			if !ok {
				return
			}
			s.logger.Debug("ETW event",
				zap.String("provider", event.System.Provider.Name),
				zap.Uint16("event_id", event.System.EventID),
			)
		}
	}
}
