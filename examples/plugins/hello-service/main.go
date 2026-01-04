// Example service plugin for afterdark-darkd
//
// This plugin demonstrates how to create a simple service plugin that
// integrates with the afterdark-darkd security daemon.
//
// Build: go build -o hello-service .
// Install: cp hello-service /var/lib/afterdark-darkd/plugins/
package main

import (
	"context"
	"fmt"
	"sync"
	"time"

	sdk "github.com/afterdarksys/afterdark-darkd/pkg/pluginsdk"
)

// HelloService is an example service plugin
type HelloService struct {
	sdk.BaseServicePlugin

	mu          sync.RWMutex
	greetings   int
	lastGreeted string
	running     bool
	stopCh      chan struct{}
}

// Info returns plugin metadata
func (s *HelloService) Info() sdk.PluginInfo {
	return sdk.PluginInfo{
		Name:        "hello-service",
		Version:     "1.0.0",
		Type:        sdk.PluginTypeService,
		Description: "Example service plugin that demonstrates the plugin SDK",
		Author:      "After Dark Systems, LLC",
		License:     "MIT",
		Capabilities: []string{
			"greet",
			"statistics",
		},
	}
}

// Configure sets up the plugin with configuration
func (s *HelloService) Configure(config map[string]interface{}) error {
	// Call base implementation
	if err := s.BaseServicePlugin.Configure(config); err != nil {
		return err
	}

	// Plugin-specific configuration
	s.SetState(sdk.PluginStateReady, "configured")
	return nil
}

// Start initializes the service
func (s *HelloService) Start(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.running {
		return fmt.Errorf("service already running")
	}

	s.running = true
	s.stopCh = make(chan struct{})
	s.SetState(sdk.PluginStateRunning, "service started")

	// Start background goroutine (example)
	go s.backgroundTask()

	return nil
}

// Stop gracefully shuts down the service
func (s *HelloService) Stop(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.running {
		return nil
	}

	close(s.stopCh)
	s.running = false
	s.SetState(sdk.PluginStateStopped, "service stopped")

	return nil
}

// Health returns the current health status
func (s *HelloService) Health() sdk.PluginHealth {
	s.mu.RLock()
	defer s.mu.RUnlock()

	health := s.BaseServicePlugin.Health()
	health.Metrics = map[string]interface{}{
		"greetings_total": s.greetings,
		"last_greeted":    s.lastGreeted,
		"running":         s.running,
	}

	return health
}

// Execute runs a specific action
func (s *HelloService) Execute(ctx context.Context, action string, params map[string]interface{}) (map[string]interface{}, error) {
	switch action {
	case "greet":
		return s.actionGreet(params)
	case "statistics":
		return s.actionStatistics()
	default:
		return nil, fmt.Errorf("unknown action: %s", action)
	}
}

func (s *HelloService) actionGreet(params map[string]interface{}) (map[string]interface{}, error) {
	name, ok := params["name"].(string)
	if !ok || name == "" {
		name = "World"
	}

	s.mu.Lock()
	s.greetings++
	s.lastGreeted = name
	count := s.greetings
	s.mu.Unlock()

	return map[string]interface{}{
		"message":         fmt.Sprintf("Hello, %s!", name),
		"greetings_total": count,
		"timestamp":       time.Now().Format(time.RFC3339),
	}, nil
}

func (s *HelloService) actionStatistics() (map[string]interface{}, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return map[string]interface{}{
		"greetings_total": s.greetings,
		"last_greeted":    s.lastGreeted,
		"running":         s.running,
	}, nil
}

func (s *HelloService) backgroundTask() {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-s.stopCh:
			return
		case <-ticker.C:
			// Example: periodic background work
			s.mu.RLock()
			count := s.greetings
			s.mu.RUnlock()
			_ = count // Could log or report metrics here
		}
	}
}

func main() {
	sdk.ServeServicePlugin(&HelloService{})
}
