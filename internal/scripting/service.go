package scripting

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/afterdarksys/afterdark-darkd/internal/service"
	"github.com/afterdarksys/afterdark-darkd/pkg/logging"
	"go.starlark.net/starlark"
	"go.uber.org/zap"
)

const ServiceName = "scripting_engine"

type Config struct {
	Enabled    bool   `mapstructure:"enabled"`
	PolicyPath string `mapstructure:"policy_path"`
}

type Service struct {
	config   *Config
	logger   *zap.Logger
	registry service.RegistryInterface

	threads map[string]*starlark.Thread
	globals starlark.StringDict

	mu      sync.RWMutex
	running bool
	stopCh  chan struct{}
}

func New(config *Config, registry service.RegistryInterface) (*Service, error) {
	if config == nil {
		config = &Config{
			Enabled:    true,
			PolicyPath: "/etc/afterdark/policies",
		}
	}

	return &Service{
		config:   config,
		logger:   logging.With(zap.String("service", ServiceName)),
		registry: registry,
		threads:  make(map[string]*starlark.Thread),
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

	s.logger.Info("starting scripting engine")

	// Create bindings
	s.globals = s.createGlobals()

	// Load initial policies
	if err := s.loadPolicies(); err != nil {
		s.logger.Warn("failed to load policies", zap.Error(err))
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
	s.logger.Info("stopped scripting engine")
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
	return service.HealthStatus{
		Status:    service.HealthHealthy,
		Message:   fmt.Sprintf("%d policies loaded", len(s.threads)),
		LastCheck: time.Now(),
	}
}

func (s *Service) createGlobals() starlark.StringDict {
	return starlark.StringDict{
		"log_info":      starlark.NewBuiltin("log_info", s.starlarkLogInfo),
		"log_warn":      starlark.NewBuiltin("log_warn", s.starlarkLogWarn),
		"kill_proc":     starlark.NewBuiltin("kill_proc", s.starlarkKillProc),
		"get_processes": starlark.NewBuiltin("get_processes", s.starlarkGetProcessList),
		"check_port":    starlark.NewBuiltin("check_port", s.starlarkIsNetworkActive),
	}
}

func (s *Service) loadPolicies() error {
	if _, err := os.Stat(s.config.PolicyPath); os.IsNotExist(err) {
		return nil
	}

	err := filepath.WalkDir(s.config.PolicyPath, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() && filepath.Ext(path) == ".star" {
			s.executeScript(path)
		}
		return nil
	})
	return err
}

func (s *Service) executeScript(path string) {
	thread := &starlark.Thread{Name: filepath.Base(path)}
	thread.Print = func(thread *starlark.Thread, msg string) {
		s.logger.Info("starlark print", zap.String("script", thread.Name), zap.String("msg", msg))
	}

	// Resource limit: Cancel execution after timeout
	const maxExecTime = 5 * time.Second
	done := make(chan struct{})
	var execErr error

	go func() {
		defer close(done)
		_, execErr = starlark.ExecFile(thread, path, nil, s.globals)
	}()

	select {
	case <-done:
		// Execution completed
	case <-time.After(maxExecTime):
		thread.Cancel("execution timeout")
		s.logger.Error("script execution timed out", zap.String("script", path), zap.Duration("timeout", maxExecTime))
		return
	case <-s.stopCh:
		thread.Cancel("service stopped")
		return
	}

	if execErr != nil {
		s.logger.Error("script execution failed", zap.String("script", path), zap.Error(execErr))
		return
	}

	s.mu.Lock()
	s.threads[path] = thread
	s.mu.Unlock()
	s.logger.Info("loaded policy script", zap.String("script", path))
}

// Builtins

func (s *Service) starlarkLogInfo(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var msg string
	if err := starlark.UnpackArgs(b.Name(), args, kwargs, "msg", &msg); err != nil {
		return nil, err
	}
	s.logger.Info(msg, zap.String("source", "policy"))
	return starlark.None, nil
}

func (s *Service) starlarkLogWarn(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var msg string
	if err := starlark.UnpackArgs(b.Name(), args, kwargs, "msg", &msg); err != nil {
		return nil, err
	}
	s.logger.Warn(msg, zap.String("source", "policy"))
	return starlark.None, nil
}

func (s *Service) starlarkKillProc(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var pid int
	if err := starlark.UnpackArgs(b.Name(), args, kwargs, "pid", &pid); err != nil {
		return nil, err
	}
	s.logger.Warn("policy requested process kill", zap.Int("pid", pid))
	// STUB: Real kill logic
	return starlark.True, nil
}
