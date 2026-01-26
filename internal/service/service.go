package service

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// Registry interface defines methods for service registry access
type RegistryInterface interface {
	Get(name string) Service
	All() []Service
	List() []string
}

// Service defines the interface all services must implement
type Service interface {
	// Name returns the service identifier
	Name() string

	// Start initializes and starts the service
	Start(ctx context.Context) error

	// Stop gracefully shuts down the service
	Stop(ctx context.Context) error

	// Health returns the current health status
	Health() HealthStatus

	// Configure updates service configuration
	Configure(config interface{}) error
}

// HealthStatus represents the health state of a service
type HealthStatus struct {
	Status    HealthState            `json:"status"`
	Message   string                 `json:"message,omitempty"`
	LastCheck time.Time              `json:"last_check"`
	Metrics   map[string]interface{} `json:"metrics,omitempty"`
}

// HealthState represents possible health states
type HealthState int

const (
	HealthUnknown HealthState = iota
	HealthHealthy
	HealthDegraded
	HealthUnhealthy
)

func (h HealthState) String() string {
	switch h {
	case HealthHealthy:
		return "healthy"
	case HealthDegraded:
		return "degraded"
	case HealthUnhealthy:
		return "unhealthy"
	default:
		return "unknown"
	}
}

func (h HealthState) MarshalJSON() ([]byte, error) {
	return []byte(`"` + h.String() + `"`), nil
}

// Registry manages service lifecycle
type Registry struct {
	mu       sync.RWMutex
	services map[string]Service
	order    []string // Tracks registration order for startup sequence
}

// NewRegistry creates a new service registry
func NewRegistry() *Registry {
	return &Registry{
		services: make(map[string]Service),
		order:    make([]string, 0),
	}
}

// Register adds a service to the registry
func (r *Registry) Register(svc Service) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	name := svc.Name()
	if _, exists := r.services[name]; exists {
		return fmt.Errorf("service %s already registered", name)
	}

	r.services[name] = svc
	r.order = append(r.order, name)
	return nil
}

// Get returns a service by name, or nil if not found
func (r *Registry) Get(name string) Service {
	r.mu.RLock()
	defer r.mu.RUnlock()

	return r.services[name]
}

// GetOk returns a service by name with existence check
func (r *Registry) GetOk(name string) (Service, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	svc, ok := r.services[name]
	return svc, ok
}

// StartAll starts all registered services in order
func (r *Registry) StartAll(ctx context.Context) error {
	r.mu.RLock()
	defer r.mu.RUnlock()

	for _, name := range r.order {
		svc := r.services[name]
		if err := svc.Start(ctx); err != nil {
			return fmt.Errorf("failed to start service %s: %w", name, err)
		}
	}
	return nil
}

// StopAll stops all registered services in reverse order
func (r *Registry) StopAll(ctx context.Context) error {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var lastErr error
	// Stop in reverse order
	for i := len(r.order) - 1; i >= 0; i-- {
		name := r.order[i]
		svc := r.services[name]
		if err := svc.Stop(ctx); err != nil {
			lastErr = fmt.Errorf("failed to stop service %s: %w", name, err)
		}
	}
	return lastErr
}

// HealthCheck returns health status for all services
func (r *Registry) HealthCheck() map[string]HealthStatus {
	r.mu.RLock()
	defer r.mu.RUnlock()

	status := make(map[string]HealthStatus)
	for name, svc := range r.services {
		status[name] = svc.Health()
	}
	return status
}

// List returns all registered service names
func (r *Registry) List() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	names := make([]string, len(r.order))
	copy(names, r.order)
	return names
}

// All returns all registered services
func (r *Registry) All() []Service {
	r.mu.RLock()
	defer r.mu.RUnlock()

	services := make([]Service, 0, len(r.order))
	for _, name := range r.order {
		services = append(services, r.services[name])
	}
	return services
}
