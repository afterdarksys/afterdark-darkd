package web

import (
	"context"
	"encoding/json"
	"github.com/afterdarksys/afterdark-darkd/internal/service"
	"go.uber.org/zap"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestWorkflowAPI(t *testing.T) {
	temp := t.TempDir()
	token := strings.Repeat("t", 64)
	tokenPath := filepath.Join(temp, "token")
	os.WriteFile(tokenPath, []byte(token), 0600)
	s := New(service.NewRegistry(), zap.NewNop(), tokenPath)
	sourceRoot := filepath.Join(temp, "sources")
	os.Mkdir(sourceRoot, 0700)
	source := filepath.Join(sourceRoot, "file")
	os.WriteFile(source, []byte("collected"), 0600)
	s.ConfigureWorkflows(filepath.Join(temp, "runs"), "")
	defer s.stopWorkflows(context.Background())
	request := func(method, path, body, auth string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, "http://localhost:7734"+path, strings.NewReader(body))
		if auth != "" {
			r.Header.Set("Authorization", "Bearer "+auth)
		}
		w := httptest.NewRecorder()
		s.httpServer.Handler.ServeHTTP(w, r)
		return w
	}
	if w := request("GET", "/api/workflows", "", ""); w.Code != 401 {
		t.Fatal(w.Code)
	}
	if w := request("GET", "/api/workflows", "", token); w.Code != 200 {
		t.Fatal(w.Code)
	}
	if w := request("POST", "/api/workflows/plan", `{"workflow":"invalid"}`, token); w.Code != 400 {
		t.Fatal(w.Code)
	}
	if w := request("POST", "/api/workflows/plan", `{"workflow":"baseline-assurance","shell":"evil"}`, token); w.Code != 400 {
		t.Fatal(w.Code)
	}
	body, _ := json.Marshal(map[string]any{"workflow": "evidence-collection", "case_id": "case", "operator": "test", "artifacts": []string{source}})
	if w := request("POST", "/api/workflows/runs", string(body), token); w.Code != 403 {
		t.Fatal(w.Code)
	}
	s.ConfigureWorkflows(filepath.Join(temp, "runs"), sourceRoot)
	outside, _ := json.Marshal(map[string]any{"workflow": "evidence-collection", "case_id": "case", "operator": "test", "artifacts": []string{tokenPath}})
	if w := request("POST", "/api/workflows/runs", string(outside), token); w.Code != 400 {
		t.Fatal(w.Code, w.Body.String())
	}
	s.workflows.mu.Lock()
	s.workflows.active = "busy"
	s.workflows.mu.Unlock()
	if w := request("POST", "/api/workflows/runs", string(body), token); w.Code != 409 {
		t.Fatal(w.Code)
	}
	s.workflows.mu.Lock()
	s.workflows.active = ""
	s.workflows.mu.Unlock()
	w := request("POST", "/api/workflows/runs", string(body), token)
	if w.Code != 202 {
		t.Fatal(w.Code, w.Body.String())
	}
	var accepted struct {
		URL string `json:"result_url"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &accepted); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		w = request("GET", accepted.URL, "", token)
		var result struct {
			Status string `json:"status"`
		}
		json.Unmarshal(w.Body.Bytes(), &result)
		if result.Status == "complete" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal(w.Code, w.Body.String())
		}
		time.Sleep(10 * time.Millisecond)
	}
	if w := request("POST", accepted.URL+"/cancel", "", token); w.Code != 409 {
		t.Fatal(w.Code)
	}
}
