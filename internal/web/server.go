package web

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"io/fs"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"embed"

	"github.com/afterdarksys/afterdark-darkd/internal/identity"
	"github.com/afterdarksys/afterdark-darkd/internal/service"
	patchsvc "github.com/afterdarksys/afterdark-darkd/internal/service/patch"
	threatsvc "github.com/afterdarksys/afterdark-darkd/internal/service/threat"
	"go.uber.org/zap"
)

//go:embed ui
var uiFiles embed.FS

const addr = "127.0.0.1:7734"

// Server is the embedded admin web server.
type Server struct {
	workflows  workflowState
	registry   *service.Registry
	httpServer *http.Server
	logger     *zap.Logger
	tokenFile  string
	started    time.Time
}

// New creates a new web server backed by the given service registry.
func New(registry *service.Registry, logger *zap.Logger, tokenFile ...string) *Server {
	s := &Server{
		registry: registry,
		logger:   logger.With(zap.String("component", "web")),
	}

	if len(tokenFile) > 0 {
		s.tokenFile = tokenFile[0]
	}
	s.started = time.Now()
	mux := http.NewServeMux()
	mux.HandleFunc("/api/workflows", s.handleWorkflows)
	mux.HandleFunc("/api/workflows/plan", s.handleWorkflowPlan)
	mux.HandleFunc("/api/workflows/runs", s.handleWorkflowRuns)
	mux.HandleFunc("/api/workflows/runs/", s.handleWorkflowRun)
	mux.HandleFunc("/api/status", s.handleStatus)
	mux.HandleFunc("/api/patches", s.handlePatches)
	mux.HandleFunc("/api/threats", s.handleThreats)
	mux.HandleFunc("/api/health", s.handleHealth)
	mux.HandleFunc("/api/account", s.handleAccount)
	sub, err := fs.Sub(uiFiles, "ui")
	if err != nil {
		panic("web: failed to create UI sub-filesystem: " + err.Error())
	}
	mux.Handle("/", http.FileServer(http.FS(sub)))

	s.httpServer = &http.Server{
		Addr:         addr,
		Handler:      s.authenticate(mux),
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	return s
}

// Addr returns the listen address.
func (s *Server) Addr() string { return "http://" + addr }

// Start starts the web server in the background.
func (s *Server) Start(ctx context.Context) error {
	if _, err := s.token(); err != nil {
		return fmt.Errorf("web API authentication unavailable: %w", err)
	}
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	s.logger.Info("starting admin web UI", zap.String("addr", s.Addr()))
	go func() {
		if err := s.httpServer.Serve(listener); err != nil && err != http.ErrServerClosed {
			s.logger.Error("web server error", zap.Error(err))
		}
	}()
	return nil
}

func (s *Server) token() (string, error) {
	data, err := os.ReadFile(s.tokenFile)
	if err != nil {
		return "", err
	}
	token := strings.TrimSpace(string(data))
	if len(token) < 32 {
		return "", fmt.Errorf("authentication token is missing or too short")
	}
	return token, nil
}

func (s *Server) authenticate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Cache-Control", "no-store")
		// Loopback binding alone does not prevent DNS rebinding.
		host, _, err := net.SplitHostPort(r.Host)
		if err != nil {
			host = r.Host
		}
		if host != "127.0.0.1" && host != "localhost" && host != "::1" {
			http.Error(w, "invalid host", http.StatusForbidden)
			return
		}
		if strings.HasPrefix(r.URL.Path, "/api/") {
			expected, err := s.token()
			supplied := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
			if err != nil || !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") || subtle.ConstantTimeCompare([]byte(expected), []byte(supplied)) != 1 {
				w.Header().Set("WWW-Authenticate", `Bearer realm="afterdark"`)
				http.Error(w, "authentication required", http.StatusUnauthorized)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

// Stop shuts down the web server gracefully.
func (s *Server) Stop(ctx context.Context) error {
	s.stopWorkflows(ctx)
	return s.httpServer.Shutdown(ctx)
}

// writeJSON encodes v as JSON and writes it to w.
func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	_ = json.NewEncoder(w).Encode(v)
}

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	id, _ := identity.LoadIdentity()

	type statusResp struct {
		Daemon     string    `json:"daemon"`
		Version    string    `json:"version"`
		Uptime     string    `json:"uptime"`
		Registered bool      `json:"registered"`
		SystemID   string    `json:"system_id,omitempty"`
		Hostname   string    `json:"hostname,omitempty"`
		OS         string    `json:"os,omitempty"`
		Arch       string    `json:"arch,omitempty"`
		Since      time.Time `json:"since"`
	}

	resp := statusResp{
		Daemon:  "running",
		Version: "0.1.0",
		Since:   s.started,
		Uptime:  time.Since(s.started).Round(time.Second).String(),
	}
	if id != nil {
		resp.Registered = id.Registered
		resp.SystemID = id.SystemID
		resp.Hostname = id.Hostname
		resp.OS = id.OS
		resp.Arch = id.Arch
	}

	writeJSON(w, resp)
}

func (s *Server) handlePatches(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	svc := s.registry.Get(patchsvc.ServiceName)
	if svc == nil {
		w.WriteHeader(http.StatusServiceUnavailable)
		writeJSON(w, map[string]any{"error": "patch service unavailable"})
		return
	}

	ps, ok := svc.(*patchsvc.Service)
	if !ok {
		writeJSON(w, map[string]any{"error": "unexpected service type"})
		return
	}

	writeJSON(w, ps.GetComplianceStatus())
}

func (s *Server) handleThreats(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	svc := s.registry.Get(threatsvc.ServiceName)
	if svc == nil {
		w.WriteHeader(http.StatusServiceUnavailable)
		writeJSON(w, map[string]any{"error": "threat service unavailable"})
		return
	}

	ts, ok := svc.(*threatsvc.Service)
	if !ok {
		writeJSON(w, map[string]any{"error": "unexpected service type"})
		return
	}

	writeJSON(w, ts.Stats())
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	writeJSON(w, s.registry.HealthCheck())
}

func (s *Server) handleAccount(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	id, _ := identity.LoadIdentity()
	if id == nil {
		writeJSON(w, map[string]any{"registered": false})
		return
	}

	// Mask the API key — show first 6 chars then asterisks
	maskedKey := ""
	if id.APIKey != "" {
		if len(id.APIKey) > 6 {
			maskedKey = id.APIKey[:6] + strings.Repeat("*", len(id.APIKey)-6)
		} else {
			maskedKey = strings.Repeat("*", len(id.APIKey))
		}
	}

	writeJSON(w, map[string]any{
		"registered":    id.Registered,
		"system_id":     id.SystemID,
		"account_email": id.AccountEmail,
		"account_id":    id.AccountID,
		"user_id":       id.UserID,
		"api_key":       maskedKey,
		"registered_at": id.RegisteredAt,
		"hostname":      id.Hostname,
		"os":            id.OS,
		"arch":          id.Arch,
	})
}
