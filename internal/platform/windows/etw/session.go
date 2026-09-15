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
	Name     string
	Session  *etw.RealTimeSession
	logger   *zap.Logger
	mu       sync.Mutex
	cancel   context.CancelFunc
	running  bool
	consumer *etw.Consumer
	done     chan struct{}
	Handler  func(*etw.Event)
	lastErr  error
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

	ctx, cancel := context.WithCancel(context.Background())
	s.cancel = cancel

	s.consumer = etw.NewRealTimeConsumer(ctx).FromSessions(s.Session)
	if err := s.consumer.Start(); err != nil {
		cancel()
		s.consumer.Stop()
		session.Stop()
		s.lastErr = err
		return err
	}
	s.running = true
	s.done = make(chan struct{})
	go s.processLoop(ctx, s.consumer)

	return nil
}

// Stop stops the ETW session
func (s *Session) Stop() error {
	s.mu.Lock()
	if s.consumer == nil || s.done == nil {
		s.mu.Unlock()
		return nil
	}
	s.running = false
	cancel, consumer, session, done := s.cancel, s.consumer, s.Session, s.done
	s.consumer = nil
	s.mu.Unlock()
	cancel()
	err := consumer.Stop()
	_ = session.Stop()
	<-done
	return err
}
func (s *Session) Healthy() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.running && s.lastErr == nil
}

func (s *Session) processLoop(ctx context.Context, consumer *etw.Consumer) {
	defer close(s.done)
	defer func() { s.mu.Lock(); s.running = false; s.mu.Unlock() }()

	for {
		select {
		case <-ctx.Done():
			return
		case event, ok := <-consumer.Events:
			if !ok {
				return
			}
			if s.Handler != nil {
				s.Handler(event)
			}
			s.logger.Debug("ETW event",
				zap.String("provider", event.System.Provider.Name),
				zap.Uint16("event_id", event.System.EventID),
			)
		}
	}
}
