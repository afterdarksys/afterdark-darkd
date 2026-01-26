package daemon

import (
	"context"
	"time"

	"github.com/afterdarksys/afterdark-darkd/internal/api/afterdark"
	"github.com/afterdarksys/afterdark-darkd/internal/api/darkapi"
	"github.com/afterdarksys/afterdark-darkd/internal/models"
	platformfactory "github.com/afterdarksys/afterdark-darkd/internal/platform/factory"
	"github.com/afterdarksys/afterdark-darkd/internal/scripting"
	"github.com/afterdarksys/afterdark-darkd/internal/service"
	"github.com/afterdarksys/afterdark-darkd/internal/service/activity"
	"github.com/afterdarksys/afterdark-darkd/internal/service/app_lockdown"
	"github.com/afterdarksys/afterdark-darkd/internal/service/baseline"
	"github.com/afterdarksys/afterdark-darkd/internal/service/canary"
	"github.com/afterdarksys/afterdark-darkd/internal/service/cloud_metadata"
	"github.com/afterdarksys/afterdark-darkd/internal/service/conntrack"
	"github.com/afterdarksys/afterdark-darkd/internal/service/device_control"
	"github.com/afterdarksys/afterdark-darkd/internal/service/dlp"
	"github.com/afterdarksys/afterdark-darkd/internal/service/dnstunnel"
	"github.com/afterdarksys/afterdark-darkd/internal/service/ebpf"
	"github.com/afterdarksys/afterdark-darkd/internal/service/esf"
	"github.com/afterdarksys/afterdark-darkd/internal/service/etw"
	"github.com/afterdarksys/afterdark-darkd/internal/service/honeypot"
	"github.com/afterdarksys/afterdark-darkd/internal/service/integrity"
	"github.com/afterdarksys/afterdark-darkd/internal/service/memscan"
	"github.com/afterdarksys/afterdark-darkd/internal/service/ml_engine"
	"github.com/afterdarksys/afterdark-darkd/internal/service/network"
	"github.com/afterdarksys/afterdark-darkd/internal/service/network_drift"
	"github.com/afterdarksys/afterdark-darkd/internal/service/patch"
	"github.com/afterdarksys/afterdark-darkd/internal/service/persistence"
	"github.com/afterdarksys/afterdark-darkd/internal/service/process"
	"github.com/afterdarksys/afterdark-darkd/internal/service/registry"
	"github.com/afterdarksys/afterdark-darkd/internal/service/siem"
	"github.com/afterdarksys/afterdark-darkd/internal/service/sysmonitor"
	"github.com/afterdarksys/afterdark-darkd/internal/service/threat"
	"github.com/afterdarksys/afterdark-darkd/internal/storage"
	storagefactory "github.com/afterdarksys/afterdark-darkd/internal/storage/factory"
	"go.uber.org/zap"
)

// InitializeServices creates and registers all daemon services
func (d *Daemon) InitializeServices() error {
	cfg := d.config

	// Get platform implementation
	plat, err := platformfactory.New()
	if err != nil {
		d.logger.Warn("failed to initialize platform", zap.Error(err))
	}

	// Get storage implementation
	storageCfg := storage.Config{
		Path:            cfg.Storage.Path,
		BackupEnabled:   cfg.Storage.BackupEnabled,
		BackupRetention: int(cfg.Storage.BackupRetention.Hours() / 24), // Convert duration to days if needed, check types
	}
	// Check storage.Config definition for types.
	// models: BackupRetention time.Duration
	// storage: BackupRetention int (days)

	store, err := storagefactory.New(cfg.Storage.Backend, storageCfg)
	if err != nil {
		d.logger.Warn("failed to initialize storage", zap.Error(err))
	}

	// Initialize API client
	apiClient := afterdark.New(&afterdark.Config{
		BaseURL: cfg.API.AfterDark.URL,
		APIKey:  cfg.API.AfterDark.APIKey,
		Timeout: cfg.API.AfterDark.Timeout,
	})

	// Initialize DarkAPI client
	darkAPI := darkapi.New(&darkapi.Config{
		BaseURL: cfg.API.DarkAPI.URL,
		APIKey:  cfg.API.DarkAPI.APIKey,
		Timeout: cfg.API.DarkAPI.Timeout,
	})

	// Register core services in dependency order

	// 1. Network service (foundational)
	if cfg.Services.NetworkMonitor.Enabled && plat != nil {
		networkSvc := network.New(&cfg.Services.NetworkMonitor, plat)
		if err := d.registry.Register(networkSvc); err != nil {
			d.logger.Error("failed to register network service", zap.Error(err))
		}
	}

	// 2. Connection tracker (depends on network)
	if cfg.Services.NetworkMonitor.Enabled {
		conntrackSvc := conntrack.New(&cfg.Services.NetworkMonitor.Tracking)
		if err := d.registry.Register(conntrackSvc); err != nil {
			d.logger.Error("failed to register connection tracker", zap.Error(err))
		}
	}

	// 3. Process monitor
	processSvc := process.New(&cfg.Services.ProcessMonitor)
	if err := d.registry.Register(processSvc); err != nil {
		d.logger.Error("failed to register process service", zap.Error(err))
	}

	// 4. Threat intelligence
	if cfg.Services.ThreatIntel.Enabled {
		threatSvc := threat.New(&cfg.Services.ThreatIntel, store, darkAPI)
		if err := d.registry.Register(threatSvc); err != nil {
			d.logger.Error("failed to register threat service", zap.Error(err))
		}
	}

	// 5. Patch monitor (depends on platform)
	if cfg.Services.PatchMonitor.Enabled && plat != nil {
		patchSvc := patch.New(&cfg.Services.PatchMonitor, plat, store, apiClient)
		if err := d.registry.Register(patchSvc); err != nil {
			d.logger.Error("failed to register patch service", zap.Error(err))
		}
	}

	// 6. Baseline scanner
	if cfg.Services.BaselineScanner.Enabled && plat != nil {
		baselineSvc := baseline.New(&cfg.Services.BaselineScanner, plat, store)
		if err := d.registry.Register(baselineSvc); err != nil {
			d.logger.Error("failed to register baseline service", zap.Error(err))
		}
	}

	// 7. C2/Beacon detection (new security feature)
	if cfg.Services.C2Detection.Enabled {
		c2Svc := NewC2DetectionService(&cfg.Services.C2Detection, d.logger)
		if err := d.registry.Register(c2Svc); err != nil {
			d.logger.Error("failed to register C2 detection service", zap.Error(err))
		}
	}

	// 8. DNS tunnel detection (new security feature)
	if cfg.Services.DNSTunnelDetection.Enabled {
		dnsSvc := dnstunnel.New(&cfg.Services.DNSTunnelDetection)
		if err := d.registry.Register(dnsSvc); err != nil {
			d.logger.Error("failed to register DNS tunnel service", zap.Error(err))
		}
	}

	// 9. Memory scanner (new security feature)
	if cfg.Services.MemoryScanner.Enabled {
		memSvc := memscan.New(&cfg.Services.MemoryScanner)
		if err := d.registry.Register(memSvc); err != nil {
			d.logger.Error("failed to register memory scanner service", zap.Error(err))
		}
	}

	// 10. Integrity Monitor
	if cfg.Services.IntegrityMonitor.Enabled {
		intSvc := integrity.New(&cfg.Services.IntegrityMonitor)
		if err := d.registry.Register(intSvc); err != nil {
			d.logger.Error("failed to register integrity monitor", zap.Error(err))
		}
	}

	// 11. Persistence Monitor
	if cfg.Services.PersistenceMonitor.Enabled {
		persSvc := persistence.New(&cfg.Services.PersistenceMonitor)
		if err := d.registry.Register(persSvc); err != nil {
			d.logger.Error("failed to register persistence monitor", zap.Error(err))
		}
	}

	// 12. System Monitor
	if cfg.Services.SysMonitor.Enabled {
		sysSvc := sysmonitor.New(&cfg.Services.SysMonitor)
		if err := d.registry.Register(sysSvc); err != nil {
			d.logger.Error("failed to register system monitor", zap.Error(err))
		}
	}

	// 13. Activity Monitor
	if cfg.Services.ActivityMonitor.Enabled {
		actSvc := activity.New(&cfg.Services.ActivityMonitor)
		if err := d.registry.Register(actSvc); err != nil {
			d.logger.Error("failed to register activity monitor", zap.Error(err))
		}
	}

	// 14. ML Engine (AI/Anomaly Detection)
	if cfg.Services.MLEngine.Enabled {
		// Convert model config to service config
		mlCfg := &ml_engine.Config{
			Enabled:          cfg.Services.MLEngine.Enabled,
			TrainingInterval: cfg.Services.MLEngine.TrainingInterval,
			ModelPath:        cfg.Services.MLEngine.ModelPath,
		}

		mlSvc, err := ml_engine.New(mlCfg, d.registry)
		if err != nil {
			d.logger.Error("failed to create ml_engine service", zap.Error(err))
		} else {
			if err := d.registry.Register(mlSvc); err != nil {
				d.logger.Error("failed to register ml_engine service", zap.Error(err))
			}
		}
	}

	// 15. Ransomware Canary
	if cfg.Services.Canary.Enabled {
		canaryCfg := &canary.Config{
			Enabled:        cfg.Services.Canary.Enabled,
			DecoyPaths:     cfg.Services.Canary.DecoyPaths,
			DecoyFilenames: cfg.Services.Canary.DecoyFilenames,
		}

		canarySvc, err := canary.New(canaryCfg, d.registry)
		if err != nil {
			d.logger.Error("failed to create canary service", zap.Error(err))
		} else {
			if err := d.registry.Register(canarySvc); err != nil {
				d.logger.Error("failed to register canary service", zap.Error(err))
			}
		}
	}

	// 16. Honeypot
	if cfg.Services.Honeypot.Enabled {
		hpCfg := &honeypot.Config{
			Enabled: cfg.Services.Honeypot.Enabled,
			Ports:   cfg.Services.Honeypot.Ports,
		}

		hpSvc, err := honeypot.New(hpCfg, d.registry)
		if err != nil {
			d.logger.Error("failed to create honeypot service", zap.Error(err))
		} else {
			if err := d.registry.Register(hpSvc); err != nil {
				d.logger.Error("failed to register honeypot service", zap.Error(err))
			}
		}
	}

	// 17. Device Control (USB)
	if cfg.Services.DeviceControl.Enabled {
		devCfg := &device_control.Config{
			Enabled:        cfg.Services.DeviceControl.Enabled,
			BlockedVendors: cfg.Services.DeviceControl.BlockedVendors,
		}

		devSvc, err := device_control.New(devCfg, d.registry)
		if err != nil {
			d.logger.Error("failed to create device_control service", zap.Error(err))
		} else {
			if err := d.registry.Register(devSvc); err != nil {
				d.logger.Error("failed to register device_control service", zap.Error(err))
			}
		}
	}

	// 18. DLP
	if cfg.Services.DLP.Enabled {
		dlpCfg := &dlp.Config{
			Enabled:       cfg.Services.DLP.Enabled,
			Keywords:      cfg.Services.DLP.Keywords,
			RegexPatterns: cfg.Services.DLP.RegexPatterns,
		}

		dlpSvc, err := dlp.New(dlpCfg, d.registry)
		if err != nil {
			d.logger.Error("failed to create dlp service", zap.Error(err))
		} else {
			if err := d.registry.Register(dlpSvc); err != nil {
				d.logger.Error("failed to register dlp service", zap.Error(err))
			}
		}
	}

	// 19. Network Drift Monitor
	if cfg.Services.NetworkDrift.Enabled {
		driftCfg := &network_drift.Config{
			Enabled:      cfg.Services.NetworkDrift.Enabled,
			ScanInterval: cfg.Services.NetworkDrift.ScanInterval,
		}

		driftSvc, err := network_drift.New(driftCfg, d.registry)
		if err != nil {
			d.logger.Error("failed to create network_drift service", zap.Error(err))
		} else {
			if err := d.registry.Register(driftSvc); err != nil {
				d.logger.Error("failed to register network_drift service", zap.Error(err))
			}
		}
	}

	// 20. Cloud Metadata Sentinel
	if cfg.Services.CloudMetadata.Enabled {
		metaCfg := &cloud_metadata.Config{
			Enabled:      cfg.Services.CloudMetadata.Enabled,
			MetadataIPs:  cfg.Services.CloudMetadata.MetadataIPs,
			AllowedUsers: cfg.Services.CloudMetadata.AllowedUsers,
		}

		metaSvc, err := cloud_metadata.New(metaCfg, d.registry)
		if err != nil {
			d.logger.Error("failed to create cloud_metadata service", zap.Error(err))
		} else {
			if err := d.registry.Register(metaSvc); err != nil {
				d.logger.Error("failed to register cloud_metadata service", zap.Error(err))
			}
		}
	}

	// 21. App Lockdown
	if cfg.Services.AppLockdown.Enabled {
		lockCfg := &app_lockdown.Config{
			Enabled:           cfg.Services.AppLockdown.Enabled,
			Allowlist:         cfg.Services.AppLockdown.Allowlist,
			BlockNewProcesses: cfg.Services.AppLockdown.BlockNewProcesses,
		}

		lockSvc, err := app_lockdown.New(lockCfg, d.registry)
		if err != nil {
			d.logger.Error("failed to create app_lockdown service", zap.Error(err))
		} else {
			if err := d.registry.Register(lockSvc); err != nil {
				d.logger.Error("failed to register app_lockdown service", zap.Error(err))
			}
		}
	}

	// 22. Scripting Engine (Starlark)
	if cfg.Services.Scripting.Enabled {
		scriptCfg := &scripting.Config{
			Enabled:    cfg.Services.Scripting.Enabled,
			PolicyPath: cfg.Services.Scripting.PolicyPath,
		}

		scriptSvc, err := scripting.New(scriptCfg, d.registry)
		if err != nil {
			d.logger.Error("failed to create scripting service", zap.Error(err))
		} else {
			if err := d.registry.Register(scriptSvc); err != nil {
				d.logger.Error("failed to register scripting service", zap.Error(err))
			}
		}
	}

	// 23. SIEM Forwarder
	if cfg.Services.SIEM.Enabled {
		siemCfg := &siem.Config{
			Enabled:   cfg.Services.SIEM.Enabled,
			URL:       cfg.Services.SIEM.URL,
			AuthToken: cfg.Services.SIEM.AuthToken,
			BatchSize: cfg.Services.SIEM.BatchSize,
		}

		siemSvc, err := siem.New(siemCfg, d.registry)
		if err != nil {
			d.logger.Error("failed to create siem service", zap.Error(err))
		} else {
			if err := d.registry.Register(siemSvc); err != nil {
				d.logger.Error("failed to register siem service", zap.Error(err))
			}
		}
	}

	// 24. eBPF Process Monitor (Linux only)
	if cfg.Services.EBPF.Enabled {
		ebpfCfg := &ebpf.Config{
			Enabled: cfg.Services.EBPF.Enabled,
		}

		ebpfSvc, err := ebpf.New(ebpfCfg, d.registry)
		if err != nil {
			d.logger.Error("failed to create ebpf service", zap.Error(err))
		} else {
			if err := d.registry.Register(ebpfSvc); err != nil {
				d.logger.Error("failed to register ebpf service", zap.Error(err))
			}
		}
	}

	// 25. ESF Endpoint Security (macOS only)
	if cfg.Services.ESF.Enabled {
		esfCfg := &esf.Config{
			Enabled: cfg.Services.ESF.Enabled,
		}

		esfSvc, err := esf.New(esfCfg, d.registry)
		if err != nil {
			d.logger.Error("failed to create esf service", zap.Error(err))
		} else {
			if err := d.registry.Register(esfSvc); err != nil {
				d.logger.Error("failed to register esf service", zap.Error(err))
			}
		}
	}

	// 26. ETW Event Trace (Windows only)
	if cfg.Services.ETW.Enabled {
		etwCfg := &etw.Config{
			Enabled: cfg.Services.ETW.Enabled,
		}

		etwSvc, err := etw.New(etwCfg, d.registry)
		if err != nil {
			d.logger.Error("failed to create etw service", zap.Error(err))
		} else {
			if err := d.registry.Register(etwSvc); err != nil {
				d.logger.Error("failed to register etw service", zap.Error(err))
			}
		}
	}

	// 27. Registry Monitor (Windows only)
	if cfg.Services.Registry.Enabled {
		regCfg := &registry.Config{
			Enabled:  cfg.Services.Registry.Enabled,
			Interval: cfg.Services.Registry.Interval,
		}

		regSvc, err := registry.New(regCfg, d.registry)
		if err != nil {
			d.logger.Error("failed to create registry service", zap.Error(err))
		} else {
			if err := d.registry.Register(regSvc); err != nil {
				d.logger.Error("failed to register registry service", zap.Error(err))
			}
		}
	}

	d.logger.Info("services initialized",
		zap.Int("registered", len(d.registry.List())))

	return nil
}

// C2DetectionService wraps the beacon analyzer as a service
type C2DetectionService struct {
	analyzer *conntrack.BeaconAnalyzer
	config   *models.C2DetectionConfig
	logger   *zap.Logger
	running  bool
}

// NewC2DetectionService creates a new C2 detection service
func NewC2DetectionService(config *models.C2DetectionConfig, logger *zap.Logger) *C2DetectionService {
	return &C2DetectionService{
		config:   config,
		analyzer: conntrack.NewBeaconAnalyzer(config, logger),
		logger:   logger.Named("c2_detection"),
	}
}

// Name returns the service name
func (s *C2DetectionService) Name() string {
	return "c2_detection"
}

// Start starts the C2 detection service
func (s *C2DetectionService) Start(ctx context.Context) error {
	s.running = true
	s.logger.Info("C2 detection service started",
		zap.Int("min_connections", s.config.MinConnections),
		zap.Float64("beacon_threshold", s.config.BeaconThreshold))
	return nil
}

// Stop stops the C2 detection service
func (s *C2DetectionService) Stop(ctx context.Context) error {
	s.running = false
	s.logger.Info("C2 detection service stopped")
	return nil
}

// Health returns service health
func (s *C2DetectionService) Health() service.HealthStatus {
	status := service.HealthHealthy
	if !s.running {
		status = service.HealthUnhealthy
	}
	return service.HealthStatus{
		Status:    status,
		Message:   "operational",
		LastCheck: time.Now(),
	}
}

// Configure updates service configuration
func (s *C2DetectionService) Configure(config interface{}) error {
	if cfg, ok := config.(*models.C2DetectionConfig); ok {
		s.config = cfg
		s.analyzer = conntrack.NewBeaconAnalyzer(cfg, s.logger)
	}
	return nil
}

// Analyzer returns the beacon analyzer
func (s *C2DetectionService) Analyzer() *conntrack.BeaconAnalyzer {
	return s.analyzer
}
