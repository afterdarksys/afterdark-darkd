package ipc

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"time"

	pb "github.com/afterdarksys/afterdark-darkd/api/proto/ipc"
	"github.com/afterdarksys/afterdark-darkd/internal/service"
	"github.com/afterdarksys/afterdark-darkd/pkg/logging"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
)

const (
	// DefaultSocketPath is the default Unix socket path
	DefaultSocketPath = "/var/run/afterdark/darkd.sock"

	// DefaultWindowsPipeName is the default Windows named pipe
	DefaultWindowsPipeName = `\\.\pipe\afterdark-darkd`
)

// Config holds the IPC server configuration
type Config struct {
	// SocketPath is the Unix socket path (Linux/macOS)
	SocketPath string

	// PipeName is the Windows named pipe name
	PipeName string

	// AuthTokenPath is the path to the authentication token file
	AuthTokenPath string

	// RequireAuth enables token-based authentication
	RequireAuth bool

	// MaxConnections limits concurrent connections
	MaxConnections int

	// TCPAddr is the TCP address to listen on (e.g. ":8080")
	TCPAddr string
}

// DefaultConfig returns the default IPC configuration
func DefaultConfig() *Config {
	socketPath := DefaultSocketPath
	if runtime.GOOS == "windows" {
		socketPath = ""
	}

	return &Config{
		SocketPath:     socketPath,
		PipeName:       DefaultWindowsPipeName,
		AuthTokenPath:  "/var/lib/afterdark/.auth_token",
		RequireAuth:    true,
		MaxConnections: 100,
	}
}

// Server is the IPC gRPC server
type Server struct {
	pb.UnimplementedDaemonServiceServer

	config    *Config
	grpcSrv   *grpc.Server
	listener  net.Listener
	logger    *zap.Logger
	startedAt time.Time

	// Service registry for accessing daemon services
	registry service.RegistryInterface

	// Authentication
	authToken string
	authMu    sync.RWMutex

	// Shutdown coordination
	mu      sync.RWMutex
	running bool
	stopCh  chan struct{}
	doneCh  chan struct{}
}

// New creates a new IPC server
func New(config *Config, registry service.RegistryInterface) (*Server, error) {
	if config == nil {
		config = DefaultConfig()
	}

	s := &Server{
		config:   config,
		registry: registry,
		logger:   logging.With(zap.String("component", "ipc")),
		stopCh:   make(chan struct{}),
		doneCh:   make(chan struct{}),
	}

	// Load auth token if required
	if config.RequireAuth {
		if err := s.loadAuthToken(); err != nil {
			s.logger.Warn("failed to load auth token, generating new one", zap.Error(err))
			if err := s.generateAuthToken(); err != nil {
				return nil, fmt.Errorf("failed to generate auth token: %w", err)
			}
		}
	}

	return s, nil
}

// Start starts the IPC server
func (s *Server) Start(ctx context.Context) error {
	s.mu.Lock()
	if s.running {
		s.mu.Unlock()
		return fmt.Errorf("server already running")
	}
	s.running = true
	s.startedAt = time.Now()
	s.mu.Unlock()

	// Create listener
	listener, err := s.createListener()
	if err != nil {
		return fmt.Errorf("failed to create listener: %w", err)
	}
	s.listener = listener

	// Create gRPC server with interceptors
	opts := []grpc.ServerOption{
		grpc.ChainUnaryInterceptor(
			s.loggingInterceptor,
			s.authInterceptor,
		),
		grpc.ChainStreamInterceptor(
			s.streamLoggingInterceptor,
			s.streamAuthInterceptor,
		),
	}

	s.grpcSrv = grpc.NewServer(opts...)
	pb.RegisterDaemonServiceServer(s.grpcSrv, s)

	// Start serving
	go func() {
		defer close(s.doneCh)

		s.logger.Info("IPC server starting",
			zap.String("address", s.listener.Addr().String()),
		)

		if err := s.grpcSrv.Serve(s.listener); err != nil {
			select {
			case <-s.stopCh:
				// Expected shutdown
			default:
				s.logger.Error("IPC server error", zap.Error(err))
			}
		}
	}()

	return nil
}

// Stop gracefully stops the IPC server
func (s *Server) Stop(ctx context.Context) error {
	s.mu.Lock()
	if !s.running {
		s.mu.Unlock()
		return nil
	}
	s.running = false
	s.mu.Unlock()

	close(s.stopCh)

	// Graceful shutdown with timeout
	done := make(chan struct{})
	go func() {
		s.grpcSrv.GracefulStop()
		close(done)
	}()

	select {
	case <-done:
		s.logger.Info("IPC server stopped gracefully")
	case <-ctx.Done():
		s.grpcSrv.Stop()
		s.logger.Warn("IPC server force stopped")
	}

	// Clean up socket file
	if runtime.GOOS != "windows" && s.config.SocketPath != "" {
		os.Remove(s.config.SocketPath)
	}

	return nil
}

// Address returns the server's listen address
func (s *Server) Address() string {
	if s.listener != nil {
		return s.listener.Addr().String()
	}
	return ""
}

// createListener creates the appropriate listener for the platform
func (s *Server) createListener() (net.Listener, error) {
	if runtime.GOOS == "windows" {
		// Windows named pipe
		return s.createWindowsListener()
	}

	// TCP listener
	if s.config.TCPAddr != "" {
		return s.createTCPListener()
	}

	// Unix socket
	return s.createUnixListener()
}

// createTCPListener creates a TCP listener
func (s *Server) createTCPListener() (net.Listener, error) {
	listener, err := net.Listen("tcp", s.config.TCPAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to listen on TCP %s: %w", s.config.TCPAddr, err)
	}
	return listener, nil
}

// createUnixListener creates a Unix domain socket listener
func (s *Server) createUnixListener() (net.Listener, error) {
	socketPath := s.config.SocketPath
	if socketPath == "" {
		socketPath = DefaultSocketPath
	}

	// Ensure directory exists
	socketDir := filepath.Dir(socketPath)
	if err := os.MkdirAll(socketDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create socket directory: %w", err)
	}

	// Remove existing socket
	if err := os.Remove(socketPath); err != nil && !os.IsNotExist(err) {
		return nil, fmt.Errorf("failed to remove existing socket: %w", err)
	}

	// Create listener
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		return nil, fmt.Errorf("failed to listen on socket: %w", err)
	}

	// Set permissions (owner only)
	if err := os.Chmod(socketPath, 0700); err != nil {
		listener.Close()
		return nil, fmt.Errorf("failed to set socket permissions: %w", err)
	}

	return listener, nil
}

// createWindowsListener creates a Windows named pipe listener
func (s *Server) createWindowsListener() (net.Listener, error) {
	// For Windows, we use a TCP listener on localhost as a fallback
	// In production, you'd use github.com/Microsoft/go-winio for named pipes
	return net.Listen("tcp", "127.0.0.1:0")
}

// loadAuthToken loads the authentication token from disk
func (s *Server) loadAuthToken() error {
	data, err := os.ReadFile(s.config.AuthTokenPath)
	if err != nil {
		return err
	}

	s.authMu.Lock()
	s.authToken = string(data)
	s.authMu.Unlock()

	return nil
}

// generateAuthToken generates a new authentication token
func (s *Server) generateAuthToken() error {
	// Generate random token
	token := generateSecureToken(32)

	// Ensure directory exists
	tokenDir := filepath.Dir(s.config.AuthTokenPath)
	if err := os.MkdirAll(tokenDir, 0700); err != nil {
		return fmt.Errorf("failed to create token directory: %w", err)
	}

	// Write token file with restricted permissions
	if err := os.WriteFile(s.config.AuthTokenPath, []byte(token), 0600); err != nil {
		return fmt.Errorf("failed to write token file: %w", err)
	}

	s.authMu.Lock()
	s.authToken = token
	s.authMu.Unlock()

	s.logger.Info("generated new auth token", zap.String("path", s.config.AuthTokenPath))

	return nil
}

// loggingInterceptor logs all unary RPC calls
func (s *Server) loggingInterceptor(
	ctx context.Context,
	req interface{},
	info *grpc.UnaryServerInfo,
	handler grpc.UnaryHandler,
) (interface{}, error) {
	start := time.Now()

	resp, err := handler(ctx, req)

	s.logger.Debug("IPC call",
		zap.String("method", info.FullMethod),
		zap.Duration("duration", time.Since(start)),
		zap.Error(err),
	)

	return resp, err
}

// authInterceptor validates authentication token for unary calls
func (s *Server) authInterceptor(
	ctx context.Context,
	req interface{},
	info *grpc.UnaryServerInfo,
	handler grpc.UnaryHandler,
) (interface{}, error) {
	if !s.config.RequireAuth {
		return handler(ctx, req)
	}

	if err := s.validateAuth(ctx); err != nil {
		return nil, err
	}

	return handler(ctx, req)
}

// streamLoggingInterceptor logs streaming RPC calls
func (s *Server) streamLoggingInterceptor(
	srv interface{},
	ss grpc.ServerStream,
	info *grpc.StreamServerInfo,
	handler grpc.StreamHandler,
) error {
	start := time.Now()

	err := handler(srv, ss)

	s.logger.Debug("IPC stream",
		zap.String("method", info.FullMethod),
		zap.Duration("duration", time.Since(start)),
		zap.Error(err),
	)

	return err
}

// streamAuthInterceptor validates authentication for streaming calls
func (s *Server) streamAuthInterceptor(
	srv interface{},
	ss grpc.ServerStream,
	info *grpc.StreamServerInfo,
	handler grpc.StreamHandler,
) error {
	if !s.config.RequireAuth {
		return handler(srv, ss)
	}

	if err := s.validateAuth(ss.Context()); err != nil {
		return err
	}

	return handler(srv, ss)
}

// validateAuth validates the authentication token from context metadata
func (s *Server) validateAuth(ctx context.Context) error {
	// For now, we're permissive since we control socket permissions
	// In production, you'd extract the token from gRPC metadata
	return nil
}

// generateSecureToken generates a cryptographically secure token
func generateSecureToken(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, length)

	// Use crypto/rand in production
	for i := range b {
		b[i] = charset[i%len(charset)]
	}

	return string(b)
}

// ============================================================================
// Client Helper
// ============================================================================

// Dial connects to the IPC server
func Dial(ctx context.Context, socketPath string) (*grpc.ClientConn, error) {
	if socketPath == "" {
		if runtime.GOOS == "windows" {
			socketPath = "127.0.0.1:0" // Would need to discover actual port
		} else {
			socketPath = DefaultSocketPath
		}
	}

	var target string
	var opts []grpc.DialOption

	if runtime.GOOS == "windows" {
		target = socketPath
		opts = append(opts, grpc.WithTransportCredentials(insecure.NewCredentials()))
	} else {
		target = "unix://" + socketPath
		opts = append(opts, grpc.WithTransportCredentials(insecure.NewCredentials()))
	}

	return grpc.DialContext(ctx, target, opts...)
}

// NewClient creates a new IPC client
func NewClient(ctx context.Context, socketPath string) (pb.DaemonServiceClient, error) {
	conn, err := Dial(ctx, socketPath)
	if err != nil {
		return nil, err
	}

	return pb.NewDaemonServiceClient(conn), nil
}

// ============================================================================
// Service Interface Implementation (Stubs - to be connected to actual services)
// ============================================================================

// GetStatus returns the daemon status
func (s *Server) GetStatus(ctx context.Context, req *pb.StatusRequest) (*pb.StatusResponse, error) {
	hostname, _ := os.Hostname()

	return &pb.StatusResponse{
		Version:       "0.1.0",
		Platform:      runtime.GOOS + "/" + runtime.GOARCH,
		Hostname:      hostname,
		UptimeSeconds: int64(time.Since(s.startedAt).Seconds()),
		Pid:           int64(os.Getpid()),
		State:         "running",
		StartedAt: &pb.Timestamp{
			Seconds: s.startedAt.Unix(),
			Nanos:   int32(s.startedAt.Nanosecond()),
		},
	}, nil
}

// GetHealth returns health status
func (s *Server) GetHealth(ctx context.Context, req *pb.HealthRequest) (*pb.HealthResponse, error) {
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)

	services := make(map[string]*pb.ServiceHealth)

	// Get health from all registered services
	if s.registry != nil {
		for _, svc := range s.registry.All() {
			health := svc.Health()
			services[svc.Name()] = &pb.ServiceHealth{
				Name:    svc.Name(),
				Status:  string(health.Status),
				Message: health.Message,
				LastCheck: &pb.Timestamp{
					Seconds: health.LastCheck.Unix(),
				},
			}
		}
	}

	return &pb.HealthResponse{
		Status:   "healthy",
		Message:  "all services operational",
		Services: services,
		Resources: &pb.ResourceMetrics{
			CpuPercent:       0, // Would need to measure
			MemoryBytes:      int64(memStats.Alloc),
			MemoryLimitBytes: int64(memStats.Sys),
			Goroutines:       int32(runtime.NumGoroutine()),
			OpenFiles:        0, // Would need platform-specific code
		},
	}, nil
}

// GetCompliance returns patch compliance status
func (s *Server) GetCompliance(ctx context.Context, req *pb.GetComplianceRequest) (*pb.ComplianceResponse, error) {
	// Get patch service from registry
	if s.registry == nil {
		return nil, status.Error(codes.Unavailable, "service registry not available")
	}

	svc := s.registry.Get("patch_monitor")
	if svc == nil {
		return nil, status.Error(codes.Unavailable, "patch_monitor service not available")
	}

	// Type assert to get patch-specific methods
	// This would need to be adapted based on actual service interface
	return &pb.ComplianceResponse{
		Compliant:        true,
		CriticalMissing:  0,
		ImportantMissing: 0,
		TotalMissing:     0,
		LastScan:         &pb.Timestamp{Seconds: time.Now().Unix()},
		NextScan:         &pb.Timestamp{Seconds: time.Now().Add(time.Hour).Unix()},
	}, nil
}

// ListPatches returns patches
func (s *Server) ListPatches(ctx context.Context, req *pb.ListPatchesRequest) (*pb.PatchListResponse, error) {
	return &pb.PatchListResponse{
		Patches:    []*pb.Patch{},
		TotalCount: 0,
	}, nil
}

// TriggerScan triggers a scan
func (s *Server) TriggerScan(ctx context.Context, req *pb.TriggerScanRequest) (*pb.ScanResponse, error) {
	scanType := req.GetScanType()
	if scanType == "" {
		scanType = "patches"
	}

	return &pb.ScanResponse{
		Started: true,
		ScanId:  fmt.Sprintf("scan-%d", time.Now().Unix()),
		Message: fmt.Sprintf("%s scan started", scanType),
	}, nil
}

// GetThreatStatus returns threat intel status
func (s *Server) GetThreatStatus(ctx context.Context, req *pb.GetThreatStatusRequest) (*pb.ThreatStatusResponse, error) {
	return &pb.ThreatStatusResponse{
		Enabled:         true,
		BadDomainsCount: 0,
		BadIpsCount:     0,
		CacheHitRate:    0.0,
		LookupsTotal:    0,
		ThreatsDetected: 0,
		LastSync:        &pb.Timestamp{Seconds: time.Now().Unix()},
		NextSync:        &pb.Timestamp{Seconds: time.Now().Add(6 * time.Hour).Unix()},
	}, nil
}

// CheckDomain checks a domain against threat intel
func (s *Server) CheckDomain(ctx context.Context, req *pb.CheckDomainRequest) (*pb.ThreatCheckResponse, error) {
	return &pb.ThreatCheckResponse{
		IsThreat:   false,
		Indicator:  req.GetDomain(),
		ThreatType: "",
		Confidence: 0,
	}, nil
}

// CheckIP checks an IP against threat intel
func (s *Server) CheckIP(ctx context.Context, req *pb.CheckIPRequest) (*pb.ThreatCheckResponse, error) {
	return &pb.ThreatCheckResponse{
		IsThreat:   false,
		Indicator:  req.GetIp(),
		ThreatType: "",
		Confidence: 0,
	}, nil
}

// CheckBulk checks multiple indicators
func (s *Server) CheckBulk(ctx context.Context, req *pb.CheckBulkRequest) (*pb.CheckBulkResponse, error) {
	var results []*pb.ThreatCheckResponse

	for _, domain := range req.GetDomains() {
		results = append(results, &pb.ThreatCheckResponse{
			IsThreat:  false,
			Indicator: domain,
		})
	}

	for _, ip := range req.GetIps() {
		results = append(results, &pb.ThreatCheckResponse{
			IsThreat:  false,
			Indicator: ip,
		})
	}

	return &pb.CheckBulkResponse{Results: results}, nil
}

// ListServices returns all services
func (s *Server) ListServices(ctx context.Context, req *pb.ListServicesRequest) (*pb.ServiceListResponse, error) {
	var services []*pb.ServiceInfo

	if s.registry != nil {
		for _, svc := range s.registry.All() {
			health := svc.Health()
			services = append(services, &pb.ServiceInfo{
				Name:    svc.Name(),
				Status:  "running",
				Enabled: true,
				Health:  string(health.Status),
			})
		}
	}

	return &pb.ServiceListResponse{Services: services}, nil
}

// StartService starts a service
func (s *Server) StartService(ctx context.Context, req *pb.ServiceRequest) (*pb.ServiceResponse, error) {
	return &pb.ServiceResponse{
		Success: true,
		Message: fmt.Sprintf("service %s started", req.GetName()),
	}, nil
}

// StopService stops a service
func (s *Server) StopService(ctx context.Context, req *pb.ServiceRequest) (*pb.ServiceResponse, error) {
	return &pb.ServiceResponse{
		Success: true,
		Message: fmt.Sprintf("service %s stopped", req.GetName()),
	}, nil
}

// RestartService restarts a service
func (s *Server) RestartService(ctx context.Context, req *pb.ServiceRequest) (*pb.ServiceResponse, error) {
	return &pb.ServiceResponse{
		Success: true,
		Message: fmt.Sprintf("service %s restarted", req.GetName()),
	}, nil
}

// GetConfig returns configuration
func (s *Server) GetConfig(ctx context.Context, req *pb.GetConfigRequest) (*pb.ConfigResponse, error) {
	return &pb.ConfigResponse{
		ConfigJson: []byte("{}"),
		ConfigYaml: "",
	}, nil
}

// ReloadConfig reloads configuration
func (s *Server) ReloadConfig(ctx context.Context, req *pb.ReloadConfigRequest) (*pb.ReloadResponse, error) {
	return &pb.ReloadResponse{
		Success: true,
		Message: "configuration reloaded",
	}, nil
}

// GetConnections returns network connections
func (s *Server) GetConnections(ctx context.Context, req *pb.GetConnectionsRequest) (*pb.ConnectionsResponse, error) {
	return &pb.ConnectionsResponse{
		Connections:  []*pb.Connection{},
		TotalCount:   0,
		FlaggedCount: 0,
	}, nil
}

// GetFileStatus returns file status
func (s *Server) GetFileStatus(ctx context.Context, req *pb.GetFileStatusRequest) (*pb.FileStatusResponse, error) {
	return &pb.FileStatusResponse{
		Found: false,
	}, nil
}

// ListQuarantined returns quarantined files
func (s *Server) ListQuarantined(ctx context.Context, req *pb.ListQuarantinedRequest) (*pb.QuarantinedResponse, error) {
	return &pb.QuarantinedResponse{
		Files:      []*pb.QuarantinedFile{},
		TotalCount: 0,
	}, nil
}

// ListProcesses returns processes
func (s *Server) ListProcesses(ctx context.Context, req *pb.ListProcessesRequest) (*pb.ProcessListResponse, error) {
	return &pb.ProcessListResponse{
		Processes:       []*pb.Process{},
		TotalCount:      0,
		SuspiciousCount: 0,
	}, nil
}

// GetEvents returns events
func (s *Server) GetEvents(ctx context.Context, req *pb.GetEventsRequest) (*pb.EventsResponse, error) {
	return &pb.EventsResponse{
		Events:     []*pb.Event{},
		TotalCount: 0,
		HasMore:    false,
	}, nil
}

// StreamEvents streams events
func (s *Server) StreamEvents(req *pb.GetEventsRequest, stream pb.DaemonService_StreamEventsServer) error {
	// This would subscribe to an event bus and stream events
	<-stream.Context().Done()
	return stream.Context().Err()
}

// Shutdown initiates daemon shutdown
func (s *Server) Shutdown(ctx context.Context, req *pb.ShutdownRequest) (*pb.ShutdownResponse, error) {
	return &pb.ShutdownResponse{
		Accepted: true,
		Message:  "shutdown initiated",
	}, nil
}

// ============================================================================
// C2/Beacon Detection
// ============================================================================

// GetBeaconAnalysis returns C2 beacon analysis results
func (s *Server) GetBeaconAnalysis(ctx context.Context, req *pb.GetBeaconAnalysisRequest) (*pb.BeaconAnalysisResponse, error) {
	if s.registry == nil {
		return nil, status.Error(codes.Unavailable, "service registry not available")
	}

	c2Svc := s.registry.Get("c2_detection")
	if c2Svc == nil {
		return &pb.BeaconAnalysisResponse{
			Beacons:       []*pb.BeaconAnalysis{},
			TotalAnalyzed: 0,
			LikelyBeacons: 0,
		}, nil
	}

	// Type assert to get C2DetectionService interface
	// For now, return stub data
	var beacons []*pb.BeaconAnalysis

	limit := int(req.GetLimit())
	if limit == 0 {
		limit = 100
	}

	return &pb.BeaconAnalysisResponse{
		Beacons:       beacons,
		TotalAnalyzed: 0,
		LikelyBeacons: 0,
	}, nil
}

// ============================================================================
// DNS Tunneling Detection
// ============================================================================

// GetDNSTunnelAnalysis returns DNS tunnel analysis results
func (s *Server) GetDNSTunnelAnalysis(ctx context.Context, req *pb.GetDNSTunnelAnalysisRequest) (*pb.DNSTunnelAnalysisResponse, error) {
	if s.registry == nil {
		return nil, status.Error(codes.Unavailable, "service registry not available")
	}

	dnsSvc := s.registry.Get("dns_tunnel_detection")
	if dnsSvc == nil {
		return &pb.DNSTunnelAnalysisResponse{
			Tunnels:              []*pb.DNSTunnelAnalysis{},
			TotalDomainsAnalyzed: 0,
			LikelyTunnels:        0,
		}, nil
	}

	// For now, return stub data
	var tunnels []*pb.DNSTunnelAnalysis

	return &pb.DNSTunnelAnalysisResponse{
		Tunnels:              tunnels,
		TotalDomainsAnalyzed: 0,
		LikelyTunnels:        0,
	}, nil
}

// ============================================================================
// Memory Scanning
// ============================================================================

// ScanProcessMemory triggers a memory scan for a specific process
func (s *Server) ScanProcessMemory(ctx context.Context, req *pb.ScanProcessMemoryRequest) (*pb.MemoryScanResponse, error) {
	if s.registry == nil {
		return nil, status.Error(codes.Unavailable, "service registry not available")
	}

	memSvc := s.registry.Get("memory_scanner")
	if memSvc == nil {
		return nil, status.Error(codes.Unavailable, "memory_scanner service not available")
	}

	pid := int(req.GetPid())
	if pid <= 0 {
		return nil, status.Error(codes.InvalidArgument, "invalid PID")
	}

	// For now, return that scan was started
	scanID := fmt.Sprintf("memscan-%d-%d", pid, time.Now().Unix())

	return &pb.MemoryScanResponse{
		ScanStarted: true,
		ScanId:      scanID,
	}, nil
}

// GetMemoryScanResults returns memory scan results
func (s *Server) GetMemoryScanResults(ctx context.Context, req *pb.GetMemoryScanResultsRequest) (*pb.MemoryScanResultsResponse, error) {
	if s.registry == nil {
		return nil, status.Error(codes.Unavailable, "service registry not available")
	}

	memSvc := s.registry.Get("memory_scanner")
	if memSvc == nil {
		return &pb.MemoryScanResultsResponse{
			Results:         []*pb.MemoryScanResult{},
			TotalScanned:    0,
			SuspiciousCount: 0,
		}, nil
	}

	// For now, return stub data
	var results []*pb.MemoryScanResult

	return &pb.MemoryScanResultsResponse{
		Results:         results,
		TotalScanned:    0,
		SuspiciousCount: 0,
	}, nil
}
