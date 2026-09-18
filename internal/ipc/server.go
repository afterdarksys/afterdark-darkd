package ipc

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	pb "github.com/afterdarksys/afterdark-darkd/api/proto/ipc"
	"github.com/afterdarksys/afterdark-darkd/internal/events"
	"github.com/afterdarksys/afterdark-darkd/internal/ipc/peercred"
	"github.com/afterdarksys/afterdark-darkd/internal/plugin"
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
	"google.golang.org/grpc/peer"
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
	PluginHost *plugin.Host
	// SocketPath is the Unix socket path (Linux/macOS)
	SocketPath string

	// PipeName is the Windows named pipe name
	PipeName string

	// AuthTokenPath is the path to the authentication token file
	AuthTokenPath string

	// RequireAuth enables token-based authentication
	RequireAuth bool

	// RequirePeerCredentials requires the connecting Unix peer UID to be
	// allowlisted in addition to the bearer token.
	RequirePeerCredentials bool

	// AllowedPeerUIDs is the set of operating-system UIDs allowed to connect.
	AllowedPeerUIDs []uint32

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
		SocketPath:             socketPath,
		PipeName:               DefaultWindowsPipeName,
		AuthTokenPath:          defaultTokenPath(),
		RequireAuth:            true,
		RequirePeerCredentials: true,
		AllowedPeerUIDs:        []uint32{peercred.CurrentUID()},
		MaxConnections:         100,
	}
}

// Server is the IPC gRPC server
type Server struct {
	pluginMu sync.Mutex
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
	if config.RequirePeerCredentials && len(config.AllowedPeerUIDs) == 0 {
		config.AllowedPeerUIDs = []uint32{peercred.CurrentUID()}
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
	transportCreds := credentials.TransportCredentials(insecure.NewCredentials())
	if runtime.GOOS != "windows" && s.config.TCPAddr == "" {
		transportCreds = &localCredentials{}
	}
	opts := []grpc.ServerOption{
		grpc.Creds(transportCreds),
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
	if runtime.GOOS == "windows" && s.config.TCPAddr == "" {
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
		certDir = filepath.Join(filepath.Dir(defaultTokenPath()), "ipc-tls")
	}

	tlsCert, _, err := ensureServerCert(certDir)
	if err != nil {
		return nil, fmt.Errorf("failed to obtain IPC TLS cert: %w", err)
	}

	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{*tlsCert},
		MinVersion:   tls.VersionTLS13,
		NextProtos:   []string{"h2"},
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
	if err := os.MkdirAll(socketDir, 0700); err != nil {
		return nil, fmt.Errorf("failed to create socket directory: %w", err)
	}
	if err := os.Chmod(socketDir, 0700); err != nil {
		return nil, fmt.Errorf("failed to restrict socket directory: %w", err)
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

// loadAuthToken loads the authentication token from disk
func (s *Server) loadAuthToken() error {
	data, err := os.ReadFile(s.config.AuthTokenPath)
	if err != nil {
		return err
	}

	token := strings.TrimSpace(string(data))
	if token == "" {
		return fmt.Errorf("authentication token is empty")
	}

	s.authMu.Lock()
	s.authToken = token
	s.authMu.Unlock()

	return nil
}

// generateAuthToken generates a new authentication token
func (s *Server) generateAuthToken() error {
	// Generate random token
	token, err := generateSecureToken(32)
	if err != nil {
		return fmt.Errorf("failed to generate token: %w", err)
	}

	// Ensure directory exists
	tokenDir := filepath.Dir(s.config.AuthTokenPath)
	if err := os.MkdirAll(tokenDir, 0700); err != nil {
		return fmt.Errorf("failed to create token directory: %w", err)
	}
	if err := os.Chmod(tokenDir, 0700); err != nil {
		return fmt.Errorf("failed to restrict token directory: %w", err)
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
		if err := s.validatePeer(ctx); err != nil {
			return nil, err
		}
		return handler(ctx, req)
	}

	if err := s.validatePeer(ctx); err != nil {
		return nil, err
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
		if err := s.validatePeer(ss.Context()); err != nil {
			return err
		}
		return handler(srv, ss)
	}

	if err := s.validatePeer(ss.Context()); err != nil {
		return err
	}
	if err := s.validateAuth(ss.Context()); err != nil {
		return err
	}

	return handler(srv, ss)
}

func (s *Server) validatePeer(ctx context.Context) error {
	if !s.config.RequirePeerCredentials || runtime.GOOS == "windows" || s.config.TCPAddr != "" {
		return nil
	}

	p, ok := peer.FromContext(ctx)
	if !ok || p.AuthInfo == nil {
		return status.Error(codes.Unauthenticated, "missing peer credentials")
	}
	info, ok := p.AuthInfo.(*localAuthInfo)
	if !ok {
		return status.Error(codes.Unauthenticated, "invalid peer credentials")
	}
	for _, allowed := range s.config.AllowedPeerUIDs {
		if info.UID == allowed {
			return nil
		}
	}
	return status.Error(codes.PermissionDenied, "peer UID is not authorized")
}

// validateAuth validates the authentication token from context metadata
func (s *Server) validateAuth(ctx context.Context) error {
	if !s.config.RequireAuth {
		return nil
	}

	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return status.Error(codes.Unauthenticated, "missing metadata")
	}

	values := md.Get("authorization")
	if len(values) == 0 {
		return status.Error(codes.Unauthenticated, "missing authorization header")
	}

	bearer := values[0]
	if !strings.HasPrefix(bearer, "Bearer ") {
		return status.Error(codes.Unauthenticated, "invalid authorization format")
	}
	token := strings.TrimPrefix(bearer, "Bearer ")

	s.authMu.RLock()
	expected := s.authToken
	s.authMu.RUnlock()

	if subtle.ConstantTimeCompare([]byte(token), []byte(expected)) != 1 {
		return status.Error(codes.Unauthenticated, "invalid token")
	}

	return nil
}

// generateSecureToken generates a cryptographically secure token.
// Returns an error if crypto/rand fails. Callers are responsible for
// passing a valid (non-zero) length; length 0 returns ("", nil).
func generateSecureToken(length int) (string, error) {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	const maxUnbiased = 248 // floor(256/62)*62 = 4*62 = 248; discard 248-255

	result := make([]byte, length)
	buf := make([]byte, length*2) // over-sample to reduce re-reads
	filled := 0
	for filled < length {
		if _, err := rand.Read(buf); err != nil {
			return "", fmt.Errorf("crypto/rand read failed: %w", err)
		}
		for _, b := range buf {
			if filled >= length {
				break
			}
			if b >= maxUnbiased {
				continue // reject to avoid modulo bias
			}
			result[filled] = charset[b%byte(len(charset))]
			filled++
		}
	}
	return string(result), nil
}

// ============================================================================
// Client Helper
// ============================================================================

// tokenCreds injects a Bearer token into every outgoing gRPC call.
type tokenCreds struct {
	token string
}

func (t *tokenCreds) GetRequestMetadata(_ context.Context, _ ...string) (map[string]string, error) {
	return map[string]string{"authorization": "Bearer " + t.token}, nil
}

func (t *tokenCreds) RequireTransportSecurity() bool { return false }

// dialTarget returns the gRPC target string for a socket path.
func dialTarget(socketPath string) string {
	if runtime.GOOS == "windows" {
		return socketPath
	}
	return "unix://" + socketPath
}

func Dial(ctx context.Context, socketPath string) (*grpc.ClientConn, error) {
	return dialWithOptions(ctx, socketPath, "", authDialOptions())
}

func DialWithCertDir(ctx context.Context, socketPath, certDir string) (*grpc.ClientConn, error) {
	return dialWithOptions(ctx, socketPath, certDir, authDialOptions())
}
func dialWithOptions(ctx context.Context, socketPath, certDir string, opts []grpc.DialOption) (*grpc.ClientConn, error) {
	if socketPath == "" {
		if runtime.GOOS == "windows" {
			socketPath = DefaultWindowsPipeName
		} else {
			socketPath = DefaultSocketPath
		}
	}

	if runtime.GOOS == "windows" && strings.HasPrefix(socketPath, `\\.\pipe\`) {
		return dialWindowsPipe(ctx, socketPath, opts...)
	}
	var target string

	isTCP := runtime.GOOS == "windows" || (len(socketPath) > 0 && socketPath[0] != '/')

	if isTCP {
		target = socketPath
		if certDir == "" {
			certDir = filepath.Join(filepath.Dir(defaultTokenPath()), "ipc-tls")
		}
		tlsCfg, err := loadClientTLSConfig(certDir)
		if err != nil {
			// Cert not found — daemon may not have started with TCP mode yet.
			return nil, fmt.Errorf("IPC TLS cert not found in %s (is the daemon running in TCP mode?): %w", certDir, err)
		}
		opts = append(opts, grpc.WithTransportCredentials(credentials.NewTLS(tlsCfg)))
	} else {
		target = "unix://" + socketPath
		opts = append(opts, grpc.WithTransportCredentials(clientTransportCredentials()))
	}

	return grpc.DialContext(ctx, target, opts...) //nolint:staticcheck
}

func DialWithToken(ctx context.Context, socketPath, token string) (*grpc.ClientConn, error) {
	return dialWithOptions(ctx, socketPath, "", []grpc.DialOption{grpc.WithPerRPCCredentials(&tokenCreds{token: token})})
}
func clientTransportCredentials() credentials.TransportCredentials {
	if runtime.GOOS != "windows" {
		return &localCredentials{}
	}
	return insecure.NewCredentials()
}

type localAuthInfo struct {
	credentials.CommonAuthInfo
	UID uint32
}

func (localAuthInfo) AuthType() string { return "unix-peer" }

type localCredentials struct{}

func (*localCredentials) ClientHandshake(_ context.Context, _ string, conn net.Conn) (net.Conn, credentials.AuthInfo, error) {
	uid, err := peercred.FromConn(conn)
	if err != nil {
		return nil, nil, err
	}
	return conn, &localAuthInfo{UID: uid}, nil
}

func (*localCredentials) ServerHandshake(conn net.Conn) (net.Conn, credentials.AuthInfo, error) {
	uid, err := peercred.FromConn(conn)
	if err != nil {
		return nil, nil, err
	}
	return conn, &localAuthInfo{UID: uid}, nil
}

func (*localCredentials) Info() credentials.ProtocolInfo {
	return credentials.ProtocolInfo{SecurityProtocol: "unix-peer"}
}

func (c *localCredentials) Clone() credentials.TransportCredentials { return c }

func (*localCredentials) OverrideServerName(string) error { return nil }

// NewClient creates an IPC client using the default local token when available.
func NewClient(ctx context.Context, socketPath string) (pb.DaemonServiceClient, error) {
	conn, err := Dial(ctx, socketPath)
	if err != nil {
		return nil, err
	}
	return pb.NewDaemonServiceClient(conn), nil
}

// NewClientWithToken creates a new IPC client that authenticates with a Bearer token.
func NewClientWithToken(ctx context.Context, socketPath, token string) (pb.DaemonServiceClient, error) {
	conn, err := DialWithToken(ctx, socketPath, token)
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
		return nil, status.Error(codes.Unavailable, "registry not available")
	}
	svc := s.registry.Get("patch_monitor")
	if svc == nil {
		return nil, status.Error(codes.Unavailable, "patch_monitor not available")
	}

	patchSvc, ok := svc.(patch.Interface)
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
	if s.registry == nil {
		return nil, status.Error(codes.Unavailable, "registry not available")
	}
	svc := s.registry.Get("patch_monitor")
	if svc == nil {
		return nil, status.Error(codes.Unavailable, "patch_monitor not available")
	}
	patchSvc, ok := svc.(patch.Interface)
	if !ok {
		return nil, status.Error(codes.Internal, "patch_monitor type assertion failed")
	}
	missing := patchSvc.GetMissingPatches()
	patches := make([]*pb.Patch, 0, len(missing))
	for _, p := range missing {
		pbp := &pb.Patch{
			Id:          p.ID,
			Name:        p.Name,
			Description: p.Description,
			Severity:    p.Severity.String(),
			Category:    p.Category.String(),
			ReleasedAt:  &pb.Timestamp{Seconds: p.ReleasedAt.Unix()},
			Cves:        p.CVEs,
			KbArticle:   p.KBArticle,
			SizeBytes:   p.Size,
		}
		if p.InstalledAt != nil {
			pbp.InstalledAt = &pb.Timestamp{Seconds: p.InstalledAt.Unix()}
		}
		patches = append(patches, pbp)
	}
	return &pb.PatchListResponse{
		Patches:    patches,
		TotalCount: int32(len(patches)),
	}, nil
}

// TriggerScan triggers a scan
func (s *Server) TriggerScan(ctx context.Context, req *pb.TriggerScanRequest) (*pb.ScanResponse, error) {
	if s.registry == nil {
		return nil, status.Error(codes.Unavailable, "service registry unavailable")
	}
	switch req.GetScanType() {
	case "", "patch", "patches":
		svc, ok := s.registry.Get("patch_monitor").(patch.Interface)
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
		return nil, status.Error(codes.Unavailable, "registry not available")
	}
	svc := s.registry.Get("threat_intel")
	if svc == nil {
		return nil, status.Error(codes.Unavailable, "threat_intel not available")
	}
	ts, ok := svc.(threat.Interface)
	if !ok {
		return nil, status.Error(codes.Internal, "threat_intel type assertion failed")
	}
	st := ts.Stats()
	return &pb.ThreatStatusResponse{
		Enabled:         true,
		BadDomainsCount: int64(st.DomainCount),
		BadIpsCount:     int64(st.IPCount),
		LastSync:        &pb.Timestamp{Seconds: st.LastSync.Unix()},
		NextSync:        &pb.Timestamp{Seconds: time.Now().Add(6 * time.Hour).Unix()},
	}, nil
}

// CheckDomain checks a domain against threat intel
func (s *Server) CheckDomain(ctx context.Context, req *pb.CheckDomainRequest) (*pb.ThreatCheckResponse, error) {
	if s.registry == nil || s.registry.Get("threat_intel") == nil {
		return nil, status.Error(codes.Unavailable, "threat intelligence unavailable")
	}
	if t, ok := s.registry.Get("threat_intel").(*threat.Service); !ok || t.GetLastSync().IsZero() || t.Health().Status != service.HealthHealthy {
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
	if t, ok := s.registry.Get("threat_intel").(*threat.Service); !ok || t.GetLastSync().IsZero() || t.Health().Status != service.HealthHealthy {
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
	if s.registry == nil {
		return nil, status.Error(codes.Unavailable, "event store unavailable")
	}
	store, ok := s.registry.Get(events.ServiceName).(*events.Store)
	if !ok {
		return nil, status.Error(codes.Unavailable, "event store unavailable")
	}
	var since time.Time
	if req.Since != nil {
		since = time.Unix(req.Since.Seconds, int64(req.Since.Nanos))
	}
	limit := int(req.GetLimit())
	if limit <= 0 || limit > 999 {
		limit = 100
	}
	records, err := store.ListRecent(ctx, limit+1, since, req.GetEventType(), req.GetSeverity())
	if err != nil {
		return nil, status.Error(codes.Unavailable, err.Error())
	}
	more := len(records) > limit
	if more {
		records = records[:limit]
	}
	out := &pb.EventsResponse{HasMore: more, TotalCount: int32(len(records))}
	for _, e := range records {
		metadata := map[string]string{
			"data":              string(e.Data),
			"endpoint_id":       e.Endpoint,
			"session_id":        e.Session,
			"schema_version":    strconv.Itoa(e.SchemaVersion),
			"collection_status": e.CollectionStatus,
			"stream_id":         e.StreamID,
			"sequence":          strconv.FormatInt(e.Sequence, 10),
			"agent_version":     e.AgentVersion,
		}
		if e.BootID != "" {
			metadata["boot_id"] = e.BootID
		}
		if e.CorrelationID != "" {
			metadata["correlation_id"] = e.CorrelationID
		}
		// Entities and facts are already bounded by the durable event envelope.
		// Keep them structured JSON instead of asking CLI/UI consumers to parse
		// each source-specific payload independently.
		if len(e.Entities) > 0 {
			if encoded, err := json.Marshal(e.Entities); err == nil {
				metadata["entities"] = string(encoded)
			}
		}
		if len(e.Facts) > 0 {
			if encoded, err := json.Marshal(e.Facts); err == nil {
				metadata["facts"] = string(encoded)
			}
		}
		out.Events = append(out.Events, &pb.Event{Id: e.ID, Type: e.Type, Severity: e.Severity, Source: e.Source, Timestamp: &pb.Timestamp{Seconds: e.Time.Unix(), Nanos: int32(e.Time.Nanosecond())}, Metadata: metadata})
	}
	return out, nil
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
