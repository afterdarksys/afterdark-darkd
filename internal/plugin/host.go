package plugin

import (
	"encoding/json"
	"fmt"
	"io"
	std_log "log"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"time"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/go-plugin"
	"go.uber.org/zap"
)

// ProtocolVersion is the plugin protocol version
const ProtocolVersion = 1

// HandshakeConfig is used to validate plugin connections
var HandshakeConfig = plugin.HandshakeConfig{
	ProtocolVersion:  ProtocolVersion,
	MagicCookieKey:   "AFTERDARK_PLUGIN",
	MagicCookieValue: "darkd-v1",
}

// PluginMap defines the available plugin types
var PluginMap = map[string]plugin.Plugin{
	"service":    &ServicePluginImpl{},
	"datasource": &DataSourcePluginImpl{},
	"storage":    &StoragePluginImpl{},
	"reporter":   &ReporterPluginImpl{},
	"cli":        &CLIPluginImpl{},
}

// LoadedPlugin represents a loaded and running plugin
type LoadedPlugin struct {
	Info       PluginInfo
	Path       string
	Client     *plugin.Client
	Raw        interface{}
	State      PluginState
	LoadedAt   time.Time
	LastHealth PluginHealth
	mu         sync.RWMutex
}

// Host manages plugin lifecycle
type Host struct {
	pluginDir string
	plugins   map[string]*LoadedPlugin
	mu        sync.RWMutex
	logger    *zap.Logger
	hcLogger  hclog.Logger
}

// NewHost creates a new plugin host
func NewHost(pluginDir string, logger *zap.Logger) *Host {
	// Create hclog adapter for go-plugin
	hcLogger := &zapHclogAdapter{logger: logger.Named("plugin")}

	return &Host{
		pluginDir: pluginDir,
		plugins:   make(map[string]*LoadedPlugin),
		logger:    logger,
		hcLogger:  hcLogger,
	}
}

// DiscoverPlugins scans the plugin directory for available plugins
func (h *Host) DiscoverPlugins() ([]string, error) {
	if _, err := os.Stat(h.pluginDir); os.IsNotExist(err) {
		return nil, nil // No plugin directory, no plugins
	}

	entries, err := os.ReadDir(h.pluginDir)
	if err != nil {
		return nil, fmt.Errorf("failed to read plugin directory: %w", err)
	}

	var plugins []string
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		path := filepath.Join(h.pluginDir, entry.Name())
		info, err := entry.Info()
		if err != nil {
			continue
		}

		// Check if executable
		if info.Mode()&0111 != 0 {
			plugins = append(plugins, path)
		}
	}

	return plugins, nil
}

// LoadPlugin loads a single plugin from the given path
func (h *Host) LoadPlugin(path string) (*LoadedPlugin, error) {
	h.mu.Lock()
	defer h.mu.Unlock()

	// Check if already loaded
	if existing, ok := h.plugins[path]; ok {
		return existing, nil
	}

	h.logger.Info("Loading plugin", zap.String("path", path))

	// Create the plugin client
	client := plugin.NewClient(&plugin.ClientConfig{
		HandshakeConfig:  HandshakeConfig,
		Plugins:          PluginMap,
		Cmd:              exec.Command(path),
		AllowedProtocols: []plugin.Protocol{plugin.ProtocolGRPC},
		Logger:           h.hcLogger,
	})

	// Connect to the plugin
	rpcClient, err := client.Client()
	if err != nil {
		client.Kill()
		return nil, fmt.Errorf("failed to connect to plugin: %w", err)
	}

	// Get plugin info to determine type
	raw, err := h.dispensePlugin(rpcClient)
	if err != nil {
		client.Kill()
		return nil, fmt.Errorf("failed to dispense plugin: %w", err)
	}

	// Get plugin info
	info, err := h.getPluginInfo(raw)
	if err != nil {
		client.Kill()
		return nil, fmt.Errorf("failed to get plugin info: %w", err)
	}

	loaded := &LoadedPlugin{
		Info:     info,
		Path:     path,
		Client:   client,
		Raw:      raw,
		State:    PluginStateReady,
		LoadedAt: time.Now(),
	}

	h.plugins[path] = loaded
	h.logger.Info("Plugin loaded successfully",
		zap.String("name", info.Name),
		zap.String("type", string(info.Type)),
		zap.String("version", info.Version),
	)

	return loaded, nil
}

// dispensePlugin tries each plugin type until one succeeds
func (h *Host) dispensePlugin(rpcClient plugin.ClientProtocol) (interface{}, error) {
	// Try each plugin type
	for name := range PluginMap {
		raw, err := rpcClient.Dispense(name)
		if err == nil {
			return raw, nil
		}
	}
	return nil, fmt.Errorf("plugin does not implement any known interface")
}

// getPluginInfo extracts info from any plugin type
func (h *Host) getPluginInfo(raw interface{}) (PluginInfo, error) {
	switch p := raw.(type) {
	case ServicePlugin:
		return p.Info(), nil
	case DataSourcePlugin:
		return p.Info(), nil
	case StoragePlugin:
		return p.Info(), nil
	case ReporterPlugin:
		return p.Info(), nil
	case CLIPlugin:
		return p.Info(), nil
	default:
		return PluginInfo{}, fmt.Errorf("unknown plugin type")
	}
}

// LoadAllPlugins discovers and loads all plugins
func (h *Host) LoadAllPlugins() error {
	paths, err := h.DiscoverPlugins()
	if err != nil {
		return err
	}

	for _, path := range paths {
		if _, err := h.LoadPlugin(path); err != nil {
			h.logger.Error("Failed to load plugin", zap.String("path", path), zap.Error(err))
			// Continue loading other plugins
		}
	}

	return nil
}

// UnloadPlugin stops and removes a plugin
func (h *Host) UnloadPlugin(path string) error {
	h.mu.Lock()
	defer h.mu.Unlock()

	loaded, ok := h.plugins[path]
	if !ok {
		return fmt.Errorf("plugin not loaded: %s", path)
	}

	loaded.mu.Lock()
	loaded.State = PluginStateStopping
	loaded.mu.Unlock()

	loaded.Client.Kill()

	loaded.mu.Lock()
	loaded.State = PluginStateStopped
	loaded.mu.Unlock()

	delete(h.plugins, path)
	h.logger.Info("Plugin unloaded", zap.String("name", loaded.Info.Name))

	return nil
}

// UnloadAllPlugins stops all loaded plugins
func (h *Host) UnloadAllPlugins() {
	h.mu.Lock()
	paths := make([]string, 0, len(h.plugins))
	for path := range h.plugins {
		paths = append(paths, path)
	}
	h.mu.Unlock()

	for _, path := range paths {
		h.UnloadPlugin(path)
	}
}

// GetPlugin returns a loaded plugin by path
func (h *Host) GetPlugin(path string) (*LoadedPlugin, bool) {
	h.mu.RLock()
	defer h.mu.RUnlock()

	p, ok := h.plugins[path]
	return p, ok
}

// GetPluginByName returns a loaded plugin by name
func (h *Host) GetPluginByName(name string) (*LoadedPlugin, bool) {
	h.mu.RLock()
	defer h.mu.RUnlock()

	for _, p := range h.plugins {
		if p.Info.Name == name {
			return p, true
		}
	}
	return nil, false
}

// ListPlugins returns all loaded plugins
func (h *Host) ListPlugins() []*LoadedPlugin {
	h.mu.RLock()
	defer h.mu.RUnlock()

	result := make([]*LoadedPlugin, 0, len(h.plugins))
	for _, p := range h.plugins {
		result = append(result, p)
	}
	return result
}

// GetServicePlugins returns all loaded service plugins
func (h *Host) GetServicePlugins() []ServicePlugin {
	h.mu.RLock()
	defer h.mu.RUnlock()

	var result []ServicePlugin
	for _, p := range h.plugins {
		if p.Info.Type == PluginTypeService {
			if svc, ok := p.Raw.(ServicePlugin); ok {
				result = append(result, svc)
			}
		}
	}
	return result
}

// GetDataSourcePlugins returns all loaded data source plugins
func (h *Host) GetDataSourcePlugins() []DataSourcePlugin {
	h.mu.RLock()
	defer h.mu.RUnlock()

	var result []DataSourcePlugin
	for _, p := range h.plugins {
		if p.Info.Type == PluginTypeDataSource {
			if ds, ok := p.Raw.(DataSourcePlugin); ok {
				result = append(result, ds)
			}
		}
	}
	return result
}

// GetStoragePlugins returns all loaded storage plugins
func (h *Host) GetStoragePlugins() []StoragePlugin {
	h.mu.RLock()
	defer h.mu.RUnlock()

	var result []StoragePlugin
	for _, p := range h.plugins {
		if p.Info.Type == PluginTypeStorage {
			if st, ok := p.Raw.(StoragePlugin); ok {
				result = append(result, st)
			}
		}
	}
	return result
}

// GetReporterPlugins returns all loaded reporter plugins
func (h *Host) GetReporterPlugins() []ReporterPlugin {
	h.mu.RLock()
	defer h.mu.RUnlock()

	var result []ReporterPlugin
	for _, p := range h.plugins {
		if p.Info.Type == PluginTypeReporter {
			if rp, ok := p.Raw.(ReporterPlugin); ok {
				result = append(result, rp)
			}
		}
	}
	return result
}

// GetCLIPlugins returns all loaded CLI plugins
func (h *Host) GetCLIPlugins() []CLIPlugin {
	h.mu.RLock()
	defer h.mu.RUnlock()

	var result []CLIPlugin
	for _, p := range h.plugins {
		if p.Info.Type == PluginTypeCLI {
			if cli, ok := p.Raw.(CLIPlugin); ok {
				result = append(result, cli)
			}
		}
	}
	return result
}

// HealthCheck performs health check on all plugins
func (h *Host) HealthCheck() map[string]PluginHealth {
	h.mu.RLock()
	defer h.mu.RUnlock()

	result := make(map[string]PluginHealth)
	for _, p := range h.plugins {
		health := h.checkPluginHealth(p)
		p.mu.Lock()
		p.LastHealth = health
		p.mu.Unlock()
		result[p.Info.Name] = health
	}
	return result
}

func (h *Host) checkPluginHealth(p *LoadedPlugin) PluginHealth {
	switch plugin := p.Raw.(type) {
	case ServicePlugin:
		return plugin.Health()
	case DataSourcePlugin:
		return plugin.Health()
	case StoragePlugin:
		return plugin.Health()
	case ReporterPlugin:
		return plugin.Health()
	case CLIPlugin:
		return plugin.Health()
	default:
		return PluginHealth{
			State:     PluginStateError,
			Message:   "unknown plugin type",
			LastCheck: time.Now(),
		}
	}
}

// zapHclogAdapter adapts zap.Logger to hclog.Logger interface
type zapHclogAdapter struct {
	logger *zap.Logger
	name   string
	args   []interface{}
}

func (z *zapHclogAdapter) Log(level hclog.Level, msg string, args ...interface{}) {
	fields := z.argsToFields(args)
	switch level {
	case hclog.Trace, hclog.Debug:
		z.logger.Debug(msg, fields...)
	case hclog.Info:
		z.logger.Info(msg, fields...)
	case hclog.Warn:
		z.logger.Warn(msg, fields...)
	case hclog.Error:
		z.logger.Error(msg, fields...)
	}
}

func (z *zapHclogAdapter) Trace(msg string, args ...interface{}) {
	z.logger.Debug(msg, z.argsToFields(args)...)
}

func (z *zapHclogAdapter) Debug(msg string, args ...interface{}) {
	z.logger.Debug(msg, z.argsToFields(args)...)
}

func (z *zapHclogAdapter) Info(msg string, args ...interface{}) {
	z.logger.Info(msg, z.argsToFields(args)...)
}

func (z *zapHclogAdapter) Warn(msg string, args ...interface{}) {
	z.logger.Warn(msg, z.argsToFields(args)...)
}

func (z *zapHclogAdapter) Error(msg string, args ...interface{}) {
	z.logger.Error(msg, z.argsToFields(args)...)
}

func (z *zapHclogAdapter) IsTrace() bool { return true }
func (z *zapHclogAdapter) IsDebug() bool { return true }
func (z *zapHclogAdapter) IsInfo() bool  { return true }
func (z *zapHclogAdapter) IsWarn() bool  { return true }
func (z *zapHclogAdapter) IsError() bool { return true }

func (z *zapHclogAdapter) ImpliedArgs() []interface{} { return z.args }

func (z *zapHclogAdapter) With(args ...interface{}) hclog.Logger {
	return &zapHclogAdapter{
		logger: z.logger,
		name:   z.name,
		args:   append(z.args, args...),
	}
}

func (z *zapHclogAdapter) Name() string { return z.name }

func (z *zapHclogAdapter) Named(name string) hclog.Logger {
	newName := name
	if z.name != "" {
		newName = z.name + "." + name
	}
	return &zapHclogAdapter{
		logger: z.logger.Named(name),
		name:   newName,
		args:   z.args,
	}
}

func (z *zapHclogAdapter) ResetNamed(name string) hclog.Logger {
	return &zapHclogAdapter{
		logger: z.logger.Named(name),
		name:   name,
		args:   z.args,
	}
}

func (z *zapHclogAdapter) SetLevel(level hclog.Level) {}

func (z *zapHclogAdapter) GetLevel() hclog.Level {
	return hclog.Debug
}

func (z *zapHclogAdapter) StandardLogger(opts *hclog.StandardLoggerOptions) *std_log.Logger {
	return nil
}

func (z *zapHclogAdapter) StandardWriter(opts *hclog.StandardLoggerOptions) io.Writer {
	return nil
}

func (z *zapHclogAdapter) argsToFields(args []interface{}) []zap.Field {
	fields := make([]zap.Field, 0, len(args)/2)
	for i := 0; i < len(args)-1; i += 2 {
		key, ok := args[i].(string)
		if !ok {
			continue
		}
		fields = append(fields, zap.Any(key, args[i+1]))
	}
	return fields
}

// Helper function to convert map to JSON bytes
func mapToJSON(m map[string]interface{}) []byte {
	if m == nil {
		return []byte("{}")
	}
	b, err := json.Marshal(m)
	if err != nil {
		return []byte("{}")
	}
	return b
}

// Helper function to convert JSON bytes to map
func jsonToMap(b []byte) map[string]interface{} {
	var m map[string]interface{}
	if err := json.Unmarshal(b, &m); err != nil {
		return nil
	}
	return m
}
