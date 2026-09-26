//go:build darwin

package esf

import (
	"context"
	"os"
	"sync"
	"time"

	"github.com/afterdarksys/afterdark-darkd/internal/events"
	"github.com/afterdarksys/afterdark-darkd/internal/platform/darwin/esf"
	"github.com/afterdarksys/afterdark-darkd/internal/service"
	"github.com/afterdarksys/afterdark-darkd/pkg/logging"
	"go.uber.org/zap"
)

const ServiceName = "esf_monitor"

type Config struct {
	Enabled bool `mapstructure:"enabled"`
	// Maintenance reports whether a signed control token opened the stop
	// window. It is read on every auth callback and must not block. Nil
	// means the window is always closed.
	Maintenance func() bool `mapstructure:"-" yaml:"-" json:"-"`
}

type Service struct {
	config   *Config
	logger   *zap.Logger
	registry service.RegistryInterface

	client *esf.Client
	// maintenance is fixed at New; it is read without locks from callbacks.
	maintenance func() bool

	mu      sync.RWMutex
	running bool
	authErr error
}

func New(config *Config, registry service.RegistryInterface) (*Service, error) {
	if config == nil {
		config = &Config{Enabled: true}
	}

	maintenance := config.Maintenance
	if maintenance == nil {
		maintenance = func() bool { return false }
	}
	return &Service{
		config:      config,
		logger:      logging.With(zap.String("service", ServiceName)),
		registry:    registry,
		maintenance: maintenance,
	}, nil
}

func (s *Service) Name() string {
	return ServiceName
}

func (s *Service) Start(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.running {
		return nil
	}

	client, err := esf.NewClient()
	if err != nil {
		// ESF requires special entitlements, so this might fail often in dev
		s.logger.Warn("failed to initialize ESF client (missing entitlements?)", zap.Error(err))
		// We return successfully so we don't crash the daemon, but service is "unhealthy"
		return nil
	}
	maintenance := s.maintenance
	esf.SetAuthorizer(func(path string, args []string, truncated bool, pid, ppid int, started time.Time) bool {
		return AuthAllows(ExecObservation{Kind: "auth_exec", Path: path, Args: args, ArgsTruncated: truncated, PID: pid, PPID: ppid, Started: started, Responded: true, Maintenance: maintenance()})
	})
	self := os.Getpid()
	esf.SetSignalAuthorizer(func(sender, target, sig int) bool {
		return DecideSignal(sender, target, self, sig, maintenance())
	})
	// Queue the journal before subscribing so auth events answered in the
	// callback are not dropped on the way into the store.
	client.Start(func(evt esf.Event) {
		s.handleEvent(evt)
	})

	if err := client.Subscribe(); err != nil {
		s.logger.Error("failed to subscribe to ESF events", zap.Error(err))
		client.Stop()
		return nil
	}
	if err := client.MuteError(); err != nil {
		s.logger.Warn("ESF notify client still sees this process", zap.Error(err))
	}
	s.authErr = client.AuthError()
	if s.authErr != nil {
		s.logger.Error("ESF auth client unavailable; exec and signal protection NOT enforced, notify monitoring continues", zap.Error(s.authErr))
	}
	s.client = client
	s.running = true
	s.logger.Info("started ESF monitor", zap.Bool("auth_enforcing", s.authErr == nil))

	return nil
}

func (s *Service) handleEvent(evt esf.Event) {
	decision := Decide(ExecObservation{
		Kind: evt.Kind, Path: evt.Path, Args: evt.Args, ArgsTruncated: evt.ArgsTruncated,
		PID: evt.PID, PPID: evt.PPID, Started: evt.Start, Responded: evt.Responded,
		Answer: evt.Answer, Fallback: evt.Fallback, TargetPID: evt.TargetPID, Signal: evt.Signal,
		Maintenance: s.maintenance(),
	})
	process := map[string]interface{}{"pid": evt.PID, "ppid": evt.PPID}
	if !evt.Start.IsZero() {
		process["start_time"] = evt.Start.UTC().Format(time.RFC3339Nano)
	}
	if evt.Path != "" && decision.EventType != "file.write" && decision.EventType != "file.unlink" {
		process["executable"] = evt.Path
	}
	entities := map[string]interface{}{"process": process}
	if evt.Path != "" && (decision.EventType == "file.write" || decision.EventType == "file.unlink") {
		entities["file"] = map[string]string{"path": evt.Path}
	}
	facts := map[string]interface{}{
		"endpoint_security.kind": evt.Kind,
		"authorization.action":   decision.Action,
		"authorization.enforced": decision.Enforced,
		"authorization.reason":   decision.Reason,
		"collection_method":      "endpoint_security",
		"process.pid":            evt.PID,
	}
	if !evt.Start.IsZero() {
		facts["process.start_time"] = evt.Start.UTC().Format(time.RFC3339Nano)
	}
	if evt.Fallback {
		facts["authorization.fallback"] = true
	}
	if evt.Kind == "auth_signal" {
		facts["signal.number"] = evt.Signal
		facts["signal.target_pid"] = evt.TargetPID
	}
	payload := map[string]interface{}{
		"collection_status": decision.CollectionStatus,
		"entities":          entities,
		"facts":             facts,
	}
	if err := events.Emit(s.registry, ServiceName, decision.EventType, decision.Severity, payload); err != nil {
		s.logger.Warn("ES event rejected", zap.Error(err))
	}
}

func (s *Service) Stop(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.running || s.client == nil {
		return nil
	}

	s.client.Stop()
	s.running = false
	s.logger.Info("stopped ESF monitor")
	return nil
}

func (s *Service) Configure(config interface{}) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if cfg, ok := config.(*Config); ok {
		s.config = cfg
	}
	return nil
}

func (s *Service) Health() service.HealthStatus {
	s.mu.RLock()
	defer s.mu.RUnlock()

	status := service.HealthHealthy
	msg := "ESF active"

	if !s.running {
		status = service.HealthUnhealthy
		msg = "service stopped"
	} else if s.client == nil {
		status = service.HealthUnhealthy
		msg = "client failed to init"
	} else if s.authErr != nil {
		status = service.HealthDegraded
		msg = "ESF notify active; auth not enforcing: " + s.authErr.Error()
	}

	return service.HealthStatus{
		Status:    status,
		Message:   msg,
		LastCheck: time.Now(),
		Metrics:   map[string]interface{}{"dropped_events": esf.DroppedEvents(), "auth_enforcing": s.running && s.client != nil && s.authErr == nil},
	}
}
