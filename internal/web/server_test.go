package web

import (
	"github.com/afterdarksys/afterdark-darkd/internal/service"
	"go.uber.org/zap"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAuthenticatedGateway(t *testing.T) {
	path := filepath.Join(t.TempDir(), "token")
	token := strings.Repeat("a", 64)
	if err := os.WriteFile(path, []byte(token), 0600); err != nil {
		t.Fatal(err)
	}
	s := New(service.NewRegistry(), zap.NewNop(), path)
	for _, tc := range []struct {
		path, host, token string
		want              int
	}{
		{"/api/status", "localhost:7734", "", 401},
		{"/api/status", "localhost:7734", "wrong", 401},
		{"/api/health", "localhost:7734", token, 200},
		{"/api/health", "attacker.example", token, 403},
		{"/api/patches", "localhost:7734", token, 503},
		{"/", "localhost:7734", "", 200},
	} {
		req := httptest.NewRequest(http.MethodGet, "http://"+tc.host+tc.path, nil)
		if tc.token != "" {
			req.Header.Set("Authorization", "Bearer "+tc.token)
		}
		w := httptest.NewRecorder()
		s.httpServer.Handler.ServeHTTP(w, req)
		if w.Code != tc.want {
			t.Errorf("%s: got %d want %d", tc.path, w.Code, tc.want)
		}
	}
	// Rotation revokes the old bearer immediately, without restarting the daemon.
	os.WriteFile(path, []byte(strings.Repeat("b", 64)), 0600)
	req := httptest.NewRequest("GET", "http://localhost/api/health", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(w, req)
	if w.Code != 401 {
		t.Fatal("revoked token accepted")
	}
}
