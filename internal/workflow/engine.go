// Package workflow coordinates fixed, versioned security adapters and preserves
// evidence. A complete run means collection completed, not that a host is compliant.
package workflow

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const MaxArtifact = 256 << 20
const MaxReport = 4 << 20

type Step struct {
	ID     string `json:"id"`
	Tool   string `json:"tool"`
	Action string `json:"action"`
}
type Definition struct {
	ID          string `json:"id"`
	Version     int    `json:"version"`
	Title       string `json:"title"`
	Description string `json:"description"`
	Steps       []Step `json:"steps"`
}
type Request struct {
	Workflow  string   `json:"workflow"`
	CaseID    string   `json:"case_id,omitempty"`
	Operator  string   `json:"operator,omitempty"`
	Artifacts []string `json:"artifacts,omitempty"`
	// SourceRoot confines daemon acquisition using os.Root, not string checks alone.
	SourceRoot string `json:"-"`
}
type Result struct {
	ID       string `json:"id"`
	Tool     string `json:"tool"`
	Status   string `json:"status"`
	Source   string `json:"source,omitempty"`
	Error    string `json:"error,omitempty"`
	File     string `json:"file,omitempty"`
	SHA256   string `json:"sha256,omitempty"`
	Bytes    int64  `json:"bytes"`
	Findings int    `json:"findings"`
}
type Manifest struct {
	SchemaVersion   int        `json:"schema_version"`
	ID              string     `json:"id"`
	Workflow        string     `json:"workflow"`
	WorkflowVersion int        `json:"workflow_version"`
	Status          string     `json:"status"`
	StartedAt       time.Time  `json:"started_at"`
	FinishedAt      *time.Time `json:"finished_at,omitempty"`
	CaseID          string     `json:"case_id,omitempty"`
	Operator        string     `json:"operator,omitempty"`
	Steps           []Result   `json:"steps"`
	Limitations     []string   `json:"limitations"`
}
type Collector func(context.Context, string) ([]byte, error)

func Catalog() []Definition {
	return []Definition{
		{"baseline-assurance", 1, "Baseline assurance", "Collect persistence, privacy, profile and storage evidence. No compliance certification or remediation.", []Step{
			{"launchsentry", "launchsentry", "scan"}, {"consentmap", "consentmap", "scan"}, {"profilescope", "profilescope", "scan"}, {"mountguard", "mountguard", "scan"},
		}},
		{"evidence-collection", 1, "Case evidence collection", "Acquire explicitly selected regular files into a case bundle; verify copies with SHA-256. Logical collection only.", []Step{{"acquire", "file-acquisition", "copy-and-hash"}}},
	}
}
func Plan(r Request) (Definition, error) {
	var d Definition
	for _, candidate := range Catalog() {
		if candidate.ID == r.Workflow {
			d = candidate
		}
	}
	if d.ID == "" {
		return d, fmt.Errorf("unknown workflow %q", r.Workflow)
	}
	if len(r.CaseID) > 128 || len(r.Operator) > 128 || strings.ContainsAny(r.CaseID+r.Operator, "\r\n\x00") {
		return d, errors.New("invalid case/operator label")
	}
	if r.Workflow == "baseline-assurance" {
		if len(r.Artifacts) > 0 || r.CaseID != "" {
			return d, errors.New("baseline workflow does not accept case artifacts")
		}
	} else {
		if strings.TrimSpace(r.CaseID) == "" || strings.TrimSpace(r.Operator) == "" || len(r.Artifacts) < 1 || len(r.Artifacts) > 32 {
			return d, errors.New("case ID, operator and 1–32 explicit artifact paths required")
		}
		seen := map[string]bool{}
		for _, p := range r.Artifacts {
			if !filepath.IsAbs(p) || strings.ContainsRune(p, 0) || seen[filepath.Clean(p)] {
				return d, errors.New("artifact paths must be unique, absolute paths")
			}
			seen[filepath.Clean(p)] = true
			if r.SourceRoot != "" {
				if _, err := relativeSource(r.SourceRoot, p); err != nil {
					return d, err
				}
			}
		}
	}
	return d, nil
}
func relativeSource(root, path string) (string, error) {
	rel, err := filepath.Rel(root, path)
	if err != nil || !filepath.IsLocal(rel) {
		return "", errors.New("artifact is outside configured evidence directory")
	}
	return rel, nil
}
func NewID() string { return hex.EncodeToString(randomBytes()) }
func randomBytes() []byte {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return b
}

func Run(ctx context.Context, r Request, bundle string, collect Collector) (Manifest, error) {
	d, err := Plan(r)
	if err != nil {
		return Manifest{}, err
	}
	if collect == nil {
		collect = Collect
	}
	if err = os.Mkdir(bundle, 0700); err != nil {
		return Manifest{}, fmt.Errorf("create new evidence bundle: %w", err)
	}
	root, err := os.OpenRoot(bundle)
	if err != nil {
		return Manifest{}, err
	}
	defer root.Close()
	m := Manifest{SchemaVersion: 1, ID: NewID(), Workflow: d.ID, WorkflowVersion: d.Version, Status: "running", StartedAt: time.Now().UTC(), CaseID: r.CaseID, Operator: r.Operator, Steps: []Result{}, Limitations: []string{
		"Collection status is not a compliance or safety verdict.",
		"SHA-256 verifies bytes against this manifest; the manifest is not signed or independently authenticated.",
		"Local execution uses the caller's OS permissions; operator labels are assertions, not verified identities.",
	}}
	if r.Workflow == "evidence-collection" {
		m.Limitations = append(m.Limitations, "Logical file copies only; not physical imaging, snapshots, or a complete chain of custody. Live sources can change during acquisition.")
	}
	if err = save(root, m); err != nil {
		return m, err
	}
	steps := d.Steps
	if r.Workflow == "evidence-collection" {
		steps = nil
		for i := range r.Artifacts {
			steps = append(steps, Step{fmt.Sprintf("artifact-%03d", i+1), "file-acquisition", "copy-and-hash"})
		}
	}
	partial := false
	for i, s := range steps {
		result := Result{ID: s.ID, Tool: s.Tool, Status: "complete"}
		if ctx.Err() != nil {
			result.Status = "cancelled"
			result.Error = ctx.Err().Error()
		} else if s.Tool == "file-acquisition" {
			result.Source = r.Artifacts[i]
			result.File = s.ID + ".bin"
			result.Bytes, result.SHA256, err = acquire(ctx, root, result.File, r.Artifacts[i], r.SourceRoot)
			if err != nil {
				result.Status = "error"
				result.Error = err.Error()
				result.File = ""
				result.SHA256 = ""
			}
		} else {
			stepCtx, cancel := context.WithTimeout(ctx, 2*time.Minute)
			data, callErr := collect(stepCtx, s.Tool)
			cancel()
			if len(data) > MaxReport {
				data = nil
				callErr = errors.New("collector output exceeded 4 MiB")
			}
			if len(data) > 0 {
				result.File = s.ID + ".json"
				if err = writeNew(root, result.File, data); err != nil {
					return m, err
				}
				hash := sha256.Sum256(data)
				result.SHA256 = hex.EncodeToString(hash[:])
				result.Bytes = int64(len(data))
			}
			result.Findings, err = validateReport(data, s.Tool)
			if err != nil {
				result.Status = "error"
				result.Error = err.Error()
			}
			if callErr != nil {
				result.Status = "error"
				result.Error = callErr.Error()
			}
		}
		if result.Status != "complete" {
			partial = true
		}
		m.Steps = append(m.Steps, result)
		if err = save(root, m); err != nil {
			return m, err
		}
	}
	m.Status = "complete"
	if partial {
		m.Status = "partial"
	}
	if ctx.Err() != nil {
		m.Status = "cancelled"
	}
	now := time.Now().UTC()
	m.FinishedAt = &now
	err = save(root, m)
	return m, err
}
func validateReport(data []byte, tool string) (int, error) {
	var r struct {
		Schema    int                `json:"schema_version"`
		Tool      string             `json:"tool"`
		Status    string             `json:"status"`
		Inventory *[]json.RawMessage `json:"inventory"`
		Findings  *[]json.RawMessage `json:"findings"`
		Errors    *[]json.RawMessage `json:"errors"`
	}
	if json.Unmarshal(data, &r) != nil || r.Schema != 1 || r.Tool != tool || r.Inventory == nil || r.Findings == nil || r.Errors == nil {
		return 0, errors.New("invalid or missing collector evidence")
	}
	n := len(*r.Findings)
	if r.Status != "complete" || len(*r.Errors) > 0 {
		return n, errors.New("collector reported incomplete evidence; inspect stored report")
	}
	return n, nil
}
func writeNew(root *os.Root, name string, data []byte) error {
	f, err := root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	_, err = f.Write(data)
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return err
	}
	return closeErr
}
func save(root *os.Root, m Manifest) error {
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	tmp := ".manifest-" + NewID()
	if err = writeNew(root, tmp, data); err != nil {
		return err
	}
	if err = root.Rename(tmp, "manifest.json"); err != nil {
		root.Remove(tmp)
		return err
	}
	return nil
}
func openSource(path, scope string) (*os.File, error) {
	if scope == "" {
		scope = filepath.Dir(path)
		path = filepath.Base(path)
	} else {
		var err error
		path, err = relativeSource(scope, path)
		if err != nil {
			return nil, err
		}
	}
	root, err := os.OpenRoot(scope)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	// Reject every symlink component. os.Root also prevents escape during races.
	cur := ""
	for _, part := range strings.Split(path, string(filepath.Separator)) {
		cur = filepath.Join(cur, part)
		info, e := root.Lstat(cur)
		if e != nil {
			return nil, e
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return nil, errors.New("symlink acquisition source rejected")
		}
	}
	before, err := root.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !before.Mode().IsRegular() {
		return nil, errors.New("acquisition source must be a regular file")
	}
	f, err := root.OpenFile(path, os.O_RDONLY|nonblock, 0)
	if err != nil {
		return nil, err
	}
	after, err := f.Stat()
	if err != nil || !after.Mode().IsRegular() || !os.SameFile(before, after) {
		f.Close()
		return nil, errors.New("source changed during open")
	}
	return f, nil
}

type contextReader struct {
	ctx context.Context
	r   io.Reader
}

func (r contextReader) Read(b []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.r.Read(b)
}
func acquire(ctx context.Context, root *os.Root, name, source, scope string) (int64, string, error) {
	in, err := openSource(source, scope)
	if err != nil {
		return 0, "", err
	}
	defer in.Close()
	before, err := in.Stat()
	if err != nil {
		return 0, "", err
	}
	if before.Size() > MaxArtifact {
		return 0, "", errors.New("artifact exceeds 256 MiB")
	}
	out, err := root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return 0, "", err
	}
	hash := sha256.New()
	n, err := io.Copy(io.MultiWriter(out, hash), io.LimitReader(contextReader{ctx, in}, MaxArtifact+1))
	if err == nil {
		err = out.Sync()
	}
	closeErr := out.Close()
	if err == nil {
		err = closeErr
	}
	after, statErr := in.Stat()
	if err == nil && (statErr != nil || n > MaxArtifact || n != before.Size() || after.Size() != before.Size() || !after.ModTime().Equal(before.ModTime())) {
		err = errors.New("source changed or exceeded collection limit")
	}
	if err != nil {
		root.Remove(name)
		return n, "", err
	}
	return n, hex.EncodeToString(hash.Sum(nil)), nil
}
func Read(bundle string) (Manifest, error) {
	var m Manifest
	f, err := openSource(filepath.Join(bundle, "manifest.json"), "")
	if err != nil {
		return m, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, MaxReport+1))
	if err != nil {
		return m, err
	}
	if len(data) > MaxReport {
		return m, errors.New("oversized manifest")
	}
	err = json.Unmarshal(data, &m)
	if err != nil {
		return m, err
	}
	if m.SchemaVersion != 1 || m.WorkflowVersion != 1 || len(m.ID) != 32 || len(m.Steps) > 32 {
		return m, errors.New("invalid manifest")
	}
	return m, nil
}
func Verify(bundle string) (Manifest, error) {
	m, err := Read(bundle)
	if err != nil {
		return m, err
	}
	if m.Status != "complete" || m.FinishedAt == nil || len(m.Steps) == 0 {
		return m, errors.New("run is not complete")
	}
	expected := map[string]string{}
	switch m.Workflow {
	case "baseline-assurance":
		for _, s := range Catalog()[0].Steps {
			expected[s.ID] = s.Tool
		}
		if len(m.Steps) != len(expected) {
			return m, errors.New("missing workflow steps")
		}
	case "evidence-collection":
		if m.CaseID == "" || m.Operator == "" {
			return m, errors.New("missing case metadata")
		}
		for i := range m.Steps {
			expected[fmt.Sprintf("artifact-%03d", i+1)] = "file-acquisition"
		}
	default:
		return m, errors.New("unknown manifest workflow")
	}
	seen := map[string]bool{}
	for _, s := range m.Steps {
		extension := ".json"
		if s.Tool == "file-acquisition" {
			extension = ".bin"
		}
		if expected[s.ID] != s.Tool || seen[s.ID] || s.Status != "complete" || s.Error != "" || s.File != s.ID+extension || filepath.Base(s.File) != s.File || s.Bytes < 0 || s.Bytes > MaxArtifact {
			return m, errors.New("invalid evidence entry")
		}
		seen[s.ID] = true
		f, e := openSource(filepath.Join(bundle, s.File), bundle)
		if e != nil {
			return m, e
		}
		h := sha256.New()
		n, e := io.Copy(h, io.LimitReader(f, MaxArtifact+1))
		f.Close()
		if e != nil || n != s.Bytes || hex.EncodeToString(h.Sum(nil)) != s.SHA256 {
			return m, fmt.Errorf("evidence verification failed: %s", s.ID)
		}
	}
	return m, nil
}
