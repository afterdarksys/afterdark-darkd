package ipc

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"time"

	pb "github.com/afterdarksys/afterdark-darkd/api/proto/ipc"
	"github.com/afterdarksys/afterdark-darkd/internal/service"
	"github.com/afterdarksys/afterdark-darkd/internal/service/patch"
	"github.com/afterdarksys/afterdark-darkd/internal/service/threat"
	"github.com/afterdarksys/afterdark-darkd/pkg/logging"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
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

	// TCPAddr is the TCP address to listen on (e.g. "127.0.0.1:8080")
	TCPAddr string

	// CertDir is the directory where the IPC TLS cert/key are stored.
	// Auto-generated on first start when TCP mode is enabled.
	CertDir string
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
	s.mu.Lock()
	s.running = true
	s.mu.Unlock()
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

// createTCPListener creates a TLS-wrapped TCP listener.
// The cert is auto-generated on first start and stored in CertDir.
func (s *Server) createTCPListener() (net.Listener, error) {
	certDir := s.config.CertDir
	if certDir == "" {
		certDir = "/var/lib/afterdark/ipc-tls"
	}

	tlsCert, _, err := ensureServerCert(certDir)
	if err != nil {
		return nil, fmt.Errorf("failed to obtain IPC TLS cert: %w", err)
	}

	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{*tlsCert},
		MinVersion:   tls.VersionTLS13,
	}

	listener, err := tls.Listen("tcp", s.config.TCPAddr, tlsCfg)
	if err != nil {
		return nil, fmt.Errorf("failed to listen on TCP %s: %w", s.config.TCPAddr, err)
	}

	s.logger.Info("IPC TCP listener using TLS",
		zap.String("addr", s.config.TCPAddr),
		zap.String("cert_dir", certDir),
	)

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
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return status.Error(codes.Unauthenticated, "missing metadata")
	}
	tokens := md.Get("authorization")
	if len(tokens) == 0 {
		return status.Error(codes.Unauthenticated, "missing authorization token")
	}
	s.authMu.RLock()
	expected := s.authToken
	s.authMu.RUnlock()
	if !hmac.Equal([]byte(tokens[0]), []byte("Bearer "+expected)) {
		return status.Error(codes.Unauthenticated, "invalid authorization token")
	}
	return nil
}

// generateSecureToken generates a cryptographically secure token
func generateSecureToken(length int) string {
	b := make([]byte, length)
	if _, err := rand.Read(b); err != nil {
		panic(fmt.Sprintf("crypto/rand failed: %v", err))
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// ============================================================================
// Client Helper
// ============================================================================

// Dial connects to the IPC server.
// For Unix sockets the OS enforces access via file permissions; insecure
// transport is standard practice there. For TCP, TLS is used with the
// auto-generated server cert as the trusted CA.
func Dial(ctx context.Context, socketPath string) (*grpc.ClientConn, error) {
	return DialWithCertDir(ctx, socketPath, "")
}

// DialWithCertDir connects to the IPC server, loading the TLS cert from
// certDir when connecting over TCP. Pass an empty string to use the default.
func DialWithCertDir(ctx context.Context, socketPath, certDir string) (*grpc.ClientConn, error) {
	if socketPath == "" {
		if runtime.GOOS == "windows" {
			socketPath = "127.0.0.1:0"
		} else {
			socketPath = DefaultSocketPath
		}
	}

	var target string
	var opts []grpc.DialOption

	isTCP := runtime.GOOS == "windows" || (len(socketPath) > 0 && socketPath[0] != '/')

	if isTCP {
		target = socketPath
		if certDir == "" {
			certDir = "/var/lib/afterdark/ipc-tls"
		}
		tlsCfg, err := loadClientTLSConfig(certDir)
		if err != nil {
			// Cert not found — daemon may not have started with TCP mode yet.
			return nil, fmt.Errorf("IPC TLS cert not found in %s (is the daemon running in TCP mode?): %w", certDir, err)
		}
		opts = append(opts, grpc.WithTransportCredentials(credentials.NewTLS(tlsCfg)))
	} else {
		target = "unix://" + socketPath
		opts = append(opts, grpc.WithTransportCredentials(insecure.NewCredentials()))
	}

	return grpc.DialContext(ctx, target, opts...) //nolint:staticcheck
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

	// Determine state string based on whether registry has services
	state := "running"

	resp := &pb.StatusResponse{
		Version:       "0.1.0",
		Platform:      runtime.GOOS + "/" + runtime.GOARCH,
		Hostname:      hostname,
		UptimeSeconds: int64(time.Since(s.startedAt).Seconds()),
		Pid:           int64(os.Getpid()),
		State:         state,
		StartedAt: &pb.Timestamp{
			Seconds: s.startedAt.Unix(),
			Nanos:   int32(s.startedAt.Nanosecond()),
		},
	}

	return resp, nil
}

// GetHealth returns health status
func (s *Server) GetHealth(ctx context.Context, req *pb.HealthRequest) (*pb.HealthResponse, error) {
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)

	services := make(map[string]*pb.ServiceHealth)
	overall := "healthy"
	if s.registry == nil {
		overall = "unavailable"
	}

	// Get health from all registered services
	if s.registry != nil {
		for _, svc := range s.registry.All() {
			health := svc.Health()
			if health.Status != service.HealthHealthy {
				overall = "degraded"
			}
			services[svc.Name()] = &pb.ServiceHealth{
				Name:    svc.Name(),
				Status:  health.Status.String(),
				Message: health.Message,
				LastCheck: &pb.Timestamp{
					Seconds: health.LastCheck.Unix(),
				},
			}
		}
	}

	return &pb.HealthResponse{
		Status:   overall,
		Message:  "aggregate service health",
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
	if s.registry == nil {
		return nil, status.Error(codes.Unavailable, "service registry not available")
	}

	svc := s.registry.Get("patch_monitor")
	if svc == nil {
		return nil, status.Error(codes.Unavailable, "patch_monitor service not available")
	}

	patchSvc, ok := svc.(*patch.Service)
	if !ok {
		return nil, status.Error(codes.Internal, "patch_monitor service type mismatch")
	}

	c := patchSvc.GetComplianceStatus()
	if !c.Valid {
		return nil, status.Error(codes.Unavailable, c.Reason)
	}

	return &pb.ComplianceResponse{
		Compliant:        c.Compliant,
		CriticalMissing:  int32(c.CriticalMissing),
		ImportantMissing: int32(c.ImportantMissing),
		TotalMissing:     int32(c.TotalMissing),
		LastScan:         &pb.Timestamp{Seconds: c.LastScan.Unix()},
		NextScan:         &pb.Timestamp{Seconds: c.NextScan.Unix()},
	}, nil
}

// ListPatches returns patches
func (s *Server) ListPatches(ctx context.Context, req *pb.ListPatchesRequest) (*pb.PatchListResponse, error) {
	return nil, status.Error(codes.Unimplemented, "ListPatches is not available")
}

// TriggerScan triggers a scan
func (s *Server) TriggerScan(ctx context.Context, req *pb.TriggerScanRequest) (*pb.ScanResponse, error) {
	if s.registry == nil {
		return nil, status.Error(codes.Unavailable, "service registry unavailable")
	}
	switch req.GetScanType() {
	case "", "patch", "patches":
		svc, ok := s.registry.Get("patch_monitor").(*patch.Service)
		if !ok {
			return nil, status.Error(codes.Unavailable, "patch monitor unavailable")
		}
		svc.TriggerScan()
	case "threats", "threat_intel":
		svc, ok := s.registry.Get("threat_intel").(*threat.Service)
		if !ok {
			return nil, status.Error(codes.Unavailable, "threat intelligence unavailable")
		}
		svc.TriggerSync()
	default:
		return nil, status.Error(codes.InvalidArgument, "unknown scan type")
	}
	return &pb.ScanResponse{Started: true, Message: "scan queued"}, nil
}

// GetThreatStatus returns threat intel status
func (s *Server) GetThreatStatus(ctx context.Context, req *pb.GetThreatStatusRequest) (*pb.ThreatStatusResponse, error) {
	if s.registry == nil {
		return nil, status.Error(codes.Unavailable, "service registry not available")
	}

	svc := s.registry.Get("threat_intel")
	if svc == nil {
		return nil, status.Error(codes.Unavailable, "threat_intel service not available")
	}

	threatSvc, ok := svc.(*threat.Service)
	if !ok {
		return nil, status.Error(codes.Internal, "threat_intel service type mismatch")
	}

	stats := threatSvc.Stats()
	lastSync := threatSvc.GetLastSync()
	nextSync := lastSync.Add(6 * time.Hour)

	return &pb.ThreatStatusResponse{
		Enabled:         true,
		BadDomainsCount: int64(stats.DomainCount),
		BadIpsCount:     int64(stats.IPCount),
		CacheHitRate:    0.0,
		LookupsTotal:    0,
		ThreatsDetected: 0,
		LastSync:        &pb.Timestamp{Seconds: lastSync.Unix()},
		NextSync:        &pb.Timestamp{Seconds: nextSync.Unix()},
	}, nil
}

// CheckDomain checks a domain against threat intel
func (s *Server) CheckDomain(ctx context.Context, req *pb.CheckDomainRequest) (*pb.ThreatCheckResponse, error) {
	if s.registry == nil || s.registry.Get("threat_intel") == nil {
		return nil, status.Error(codes.Unavailable, "threat intelligence unavailable")
	}
	if t, ok := s.registry.Get("threat_intel").(*threat.Service); !ok || t.GetLastSync().IsZero() {
		return nil, status.Error(codes.Unavailable, "threat intelligence has no successful sync")
	}

	domain := req.GetDomain()

	if s.registry != nil {
		svc := s.registry.Get("threat_intel")
		if svc != nil {
			if threatSvc, ok := svc.(*threat.Service); ok {
				isMalicious, info := threatSvc.IsDomainMalicious(domain)
				if isMalicious && info != nil {
					return &pb.ThreatCheckResponse{
						IsThreat:   true,
						Indicator:  domain,
						ThreatType: info.Type,
						Confidence: 90,
					}, nil
				}
			}
		}
	}

	return &pb.ThreatCheckResponse{
		IsThreat:   false,
		Indicator:  domain,
		ThreatType: "",
		Confidence: 0,
	}, nil
}

// CheckIP checks an IP against threat intel
func (s *Server) CheckIP(ctx context.Context, req *pb.CheckIPRequest) (*pb.ThreatCheckResponse, error) {
	if s.registry == nil || s.registry.Get("threat_intel") == nil {
		return nil, status.Error(codes.Unavailable, "threat intelligence unavailable")
	}
	if t, ok := s.registry.Get("threat_intel").(*threat.Service); !ok || t.GetLastSync().IsZero() {
		return nil, status.Error(codes.Unavailable, "threat intelligence has no successful sync")
	}

	ip := req.GetIp()

	if s.registry != nil {
		svc := s.registry.Get("threat_intel")
		if svc != nil {
			if threatSvc, ok := svc.(*threat.Service); ok {
				isMalicious, info := threatSvc.IsIPMalicious(ip)
				if isMalicious && info != nil {
					return &pb.ThreatCheckResponse{
						IsThreat:   true,
						Indicator:  ip,
						ThreatType: info.Type,
						Confidence: 90,
					}, nil
				}
			}
		}
	}

	return &pb.ThreatCheckResponse{
		IsThreat:   false,
		Indicator:  ip,
		ThreatType: "",
		Confidence: 0,
	}, nil
}

// CheckBulk checks multiple indicators
func (s *Server) CheckBulk(ctx context.Context, req *pb.CheckBulkRequest) (*pb.CheckBulkResponse, error) {
	results := make([]*pb.ThreatCheckResponse, 0, len(req.GetDomains())+len(req.GetIps()))
	for _, domain := range req.GetDomains() {
		result, err := s.CheckDomain(ctx, &pb.CheckDomainRequest{Domain: domain})
		if err != nil {
			return nil, err
		}
		results = append(results, result)
	}
	for _, ip := range req.GetIps() {
		result, err := s.CheckIP(ctx, &pb.CheckIPRequest{Ip: ip})
		if err != nil {
			return nil, err
		}
		results = append(results, result)
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
				Status:  health.Status.String(),
				Enabled: true,
				Health:  health.Status.String(),
			})
		}
	}

	return &pb.ServiceListResponse{Services: services}, nil
}

// StartService starts a service
func (s *Server) StartService(ctx context.Context, req *pb.ServiceRequest) (*pb.ServiceResponse, error) {
	return nil, status.Error(codes.Unimplemented, "StartService is not available")
}

// StopService stops a service
func (s *Server) StopService(ctx context.Context, req *pb.ServiceRequest) (*pb.ServiceResponse, error) {
	return nil, status.Error(codes.Unimplemented, "StopService is not available")
}

// RestartService restarts a service
func (s *Server) RestartService(ctx context.Context, req *pb.ServiceRequest) (*pb.ServiceResponse, error) {
	return nil, status.Error(codes.Unimplemented, "RestartService is not available")
}

// GetConfig returns configuration
func (s *Server) GetConfig(ctx context.Context, req *pb.GetConfigRequest) (*pb.ConfigResponse, error) {
	return nil, status.Error(codes.Unimplemented, "GetConfig is not available")
}

// ReloadConfig reloads configuration
func (s *Server) ReloadConfig(ctx context.Context, req *pb.ReloadConfigRequest) (*pb.ReloadResponse, error) {
	return nil, status.Error(codes.Unimplemented, "ReloadConfig is not available")
}

// GetConnections returns network connections
func (s *Server) GetConnections(ctx context.Context, req *pb.GetConnectionsRequest) (*pb.ConnectionsResponse, error) {
	return nil, status.Error(codes.Unimplemented, "GetConnections is not available")
}

// GetFileStatus returns file status
func (s *Server) GetFileStatus(ctx context.Context, req *pb.GetFileStatusRequest) (*pb.FileStatusResponse, error) {
	return nil, status.Error(codes.Unimplemented, "GetFileStatus is not available")
}

// ListQuarantined returns quarantined files
func (s *Server) ListQuarantined(ctx context.Context, req *pb.ListQuarantinedRequest) (*pb.QuarantinedResponse, error) {
	return nil, status.Error(codes.Unimplemented, "ListQuarantined is not available")
}

// ListProcesses returns processes
func (s *Server) ListProcesses(ctx context.Context, req *pb.ListProcessesRequest) (*pb.ProcessListResponse, error) {
	return nil, status.Error(codes.Unimplemented, "ListProcesses is not available")
}

// GetEvents returns events
func (s *Server) GetEvents(ctx context.Context, req *pb.GetEventsRequest) (*pb.EventsResponse, error) {
	return nil, status.Error(codes.Unimplemented, "GetEvents is not available")
}

// StreamEvents streams events
func (s *Server) StreamEvents(req *pb.GetEventsRequest, stream pb.DaemonService_StreamEventsServer) error {
	return status.Error(codes.Unimplemented, "event streaming is not available")
}

// Shutdown initiates daemon shutdown
func (s *Server) Shutdown(ctx context.Context, req *pb.ShutdownRequest) (*pb.ShutdownResponse, error) {
	return nil, status.Error(codes.Unimplemented, "Shutdown is not available")
}

// ============================================================================
// C2/Beacon Detection
// ============================================================================

// GetBeaconAnalysis returns C2 beacon analysis results
func (s *Server) GetBeaconAnalysis(ctx context.Context, req *pb.GetBeaconAnalysisRequest) (*pb.BeaconAnalysisResponse, error) {
	return nil, status.Error(codes.Unimplemented, "GetBeaconAnalysis is not available")
}

// ============================================================================
// DNS Tunneling Detection
// ============================================================================

// GetDNSTunnelAnalysis returns DNS tunnel analysis results
func (s *Server) GetDNSTunnelAnalysis(ctx context.Context, req *pb.GetDNSTunnelAnalysisRequest) (*pb.DNSTunnelAnalysisResponse, error) {
	return nil, status.Error(codes.Unimplemented, "GetDNSTunnelAnalysis is not available")
}

// ============================================================================
// Memory Scanning
// ============================================================================

// ScanProcessMemory triggers a memory scan for a specific process
func (s *Server) ScanProcessMemory(ctx context.Context, req *pb.ScanProcessMemoryRequest) (*pb.MemoryScanResponse, error) {
	return nil, status.Error(codes.Unimplemented, "ScanProcessMemory is not available")
}

// GetMemoryScanResults returns memory scan results
func (s *Server) GetMemoryScanResults(ctx context.Context, req *pb.GetMemoryScanResultsRequest) (*pb.MemoryScanResultsResponse, error) {
	return nil, status.Error(codes.Unimplemented, "GetMemoryScanResults is not available")
}
