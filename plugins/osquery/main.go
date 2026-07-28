package main

import (
	"context"
	"fmt"
	"os"

	sdk "github.com/afterdarksys/afterdark-darkd/pkg/pluginsdk"
)

type OsqueryPlugin struct {
	sdk.BaseServicePlugin
	manager *OsqueryManager
}

func (p *OsqueryPlugin) Info() sdk.PluginInfo {
	return sdk.PluginInfo{
		Name:        "osquery",
		Version:     "1.0.0",
		Type:        sdk.PluginTypeService,
		Description: "Manages osqueryd client for fleet visibility",
		Author:      "AfterDark Systems",
	}
}

func (p *OsqueryPlugin) Configure(config map[string]interface{}) error {
	p.BaseServicePlugin.Configure(config)

	cfg, err := ParseConfig(config)
	if err != nil {
		return fmt.Errorf("invalid configuration: %w", err)
	}

	// Ensure plugin directory exists for secrets/db
	// We assume the host daemon provides us a safe working directory or we use a standard location.
	// For this generic implementation, let's assume we can write to ./data relative to execution or similar?
	// Better: let's use a temp dir or a configured data dir if available.
	// In the SDK, usually the plugin runs with CWD as the plugin dir or similar.
	// Let's assume CWD is safe for now as per SDK patterns.
	cwd, _ := os.Getwd()
	if p.manager == nil {
		p.manager = NewManager(cwd)
	}

	p.manager.Configure(cfg)
	return nil
}

func (p *OsqueryPlugin) Start(ctx context.Context) error {
	if err := p.BaseServicePlugin.Start(ctx); err != nil {
		return err
	}

	if p.manager == nil {
		return fmt.Errorf("manager not initialized")
	}

	if err := p.manager.Start(ctx); err != nil {
		p.SetState(sdk.PluginStateError, err.Error())
		return err
	}

	p.SetState(sdk.PluginStateRunning, "osqueryd running")
	return nil
}

func (p *OsqueryPlugin) Stop(ctx context.Context) error {
	if p.manager != nil {
		p.manager.Stop(ctx)
	}
	return p.BaseServicePlugin.Stop(ctx)
}

func (p *OsqueryPlugin) Health() sdk.PluginHealth {
	health := sdk.PluginHealth{
		State: sdk.PluginStateRunning,
	}

	if p.manager != nil {
		status := p.manager.Status()
		if running, ok := status["running"].(bool); !ok || !running {
			health.State = sdk.PluginStateError
			health.Message = "osqueryd process not running"
		}
	} else {
		health.State = sdk.PluginStateUnknown
	}

	return health
}

func (p *OsqueryPlugin) Execute(ctx context.Context, action string, params map[string]interface{}) (map[string]interface{}, error) {
	switch action {
	case "status":
		if p.manager == nil {
			return nil, fmt.Errorf("manager not initialized")
		}
		return p.manager.Status(), nil
	default:
		return nil, fmt.Errorf("unknown action: %s", action)
	}
}

func main() {
	sdk.ServeServicePlugin(&OsqueryPlugin{})
}
