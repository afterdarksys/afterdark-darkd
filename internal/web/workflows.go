package web

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/afterdarksys/afterdark-darkd/internal/workflow"
	"go.uber.org/zap"
)

type workflowState struct {
	mu           sync.Mutex
	root         string
	evidenceRoot string
	active       string
	cancel       context.CancelFunc
	stopped      bool
	wg           sync.WaitGroup
	failures     map[string]string
}

// ConfigureWorkflows is called before serving. Acquisition is disabled unless
// evidenceRoot is an absolute, administrator-configured staging directory.
func (s *Server) ConfigureWorkflows(root, evidenceRoot string) {
	s.workflows.mu.Lock()
	defer s.workflows.mu.Unlock()
	s.workflows.root = root
	s.workflows.evidenceRoot = evidenceRoot
}
func (s *Server) handleWorkflows(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", 405)
		return
	}
	writeJSON(w, workflow.Catalog())
}
func decodeWorkflow(w http.ResponseWriter, r *http.Request) (workflow.Request, error) {
	var req workflow.Request
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&req); err != nil {
		return req, err
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return req, errors.New("expected one request object")
	}
	return req, nil
}
func (s *Server) handleWorkflowPlan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", 405)
		return
	}
	req, err := decodeWorkflow(w, r)
	if err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	d, err := workflow.Plan(req)
	if err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	writeJSON(w, d)
}
func (s *Server) handleWorkflowRuns(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", 405)
		return
	}
	req, err := decodeWorkflow(w, r)
	if err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	state := &s.workflows
	state.mu.Lock()
	defer state.mu.Unlock()
	if !filepath.IsAbs(state.root) || state.stopped {
		http.Error(w, "workflow service unavailable", 503)
		return
	}
	if req.Workflow == "evidence-collection" {
		if !filepath.IsAbs(state.evidenceRoot) {
			http.Error(w, "API acquisition is disabled; configure workflow_evidence_dir", 403)
			return
		}
		req.SourceRoot = state.evidenceRoot
	}
	if _, err = workflow.Plan(req); err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	if state.active != "" {
		http.Error(w, "a workflow is already active", 409)
		return
	}
	if err = os.MkdirAll(state.root, 0700); err != nil {
		http.Error(w, "cannot create workflow store", 500)
		return
	}
	info, err := os.Lstat(state.root)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0077 != 0 {
		http.Error(w, "workflow store must be a private directory", 500)
		return
	}
	id := workflow.NewID()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	state.active = id
	state.cancel = cancel
	state.wg.Add(1)
	go func() {
		defer state.wg.Done()
		defer cancel()
		_, runErr := workflow.Run(ctx, req, filepath.Join(state.root, id), nil)
		state.mu.Lock()
		defer state.mu.Unlock()
		if runErr != nil {
			if state.failures == nil {
				state.failures = map[string]string{}
			}
			state.failures[id] = "workflow persistence failed; inspect daemon logs and bundle"
			s.logger.Error("workflow failed", zap.Error(runErr))
		}
		state.active = ""
		state.cancel = nil
	}()
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	writeJSON(w, map[string]string{"bundle_id": id, "status": "accepted", "result_url": "/api/workflows/runs/" + id})
}

var workflowID = regexp.MustCompile(`^[a-f0-9]{32}$`)

func (s *Server) handleWorkflowRun(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/api/workflows/runs/")
	cancelRequest := strings.HasSuffix(path, "/cancel")
	id := strings.TrimSuffix(path, "/cancel")
	if !workflowID.MatchString(id) {
		http.Error(w, "invalid bundle ID", 400)
		return
	}
	state := &s.workflows
	state.mu.Lock()
	defer state.mu.Unlock()
	if cancelRequest {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", 405)
			return
		}
		if state.active != id || state.cancel == nil {
			http.Error(w, "run is not active", 409)
			return
		}
		state.cancel()
		writeJSON(w, map[string]string{"bundle_id": id, "status": "cancelling"})
		return
	}
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", 405)
		return
	}
	if state.root == "" {
		http.Error(w, "workflow store unavailable", 503)
		return
	}
	if failure := state.failures[id]; failure != "" {
		http.Error(w, failure, 500)
		return
	}
	m, err := workflow.Read(filepath.Join(state.root, id))
	if err != nil {
		if state.active == id && os.IsNotExist(err) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(202)
			writeJSON(w, map[string]string{"bundle_id": id, "status": "starting"})
			return
		}
		http.Error(w, "bundle unavailable or invalid", 404)
		return
	}
	if m.Status == "running" && state.active != id {
		m.Status = "interrupted"
	}
	writeJSON(w, m)
}
func (s *Server) stopWorkflows(ctx context.Context) {
	state := &s.workflows
	state.mu.Lock()
	state.stopped = true
	if state.cancel != nil {
		state.cancel()
	}
	state.mu.Unlock()
	done := make(chan struct{})
	go func() { state.wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-ctx.Done():
	}
}
