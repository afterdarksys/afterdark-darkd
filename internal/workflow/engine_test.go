package workflow

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestAcquisitionAndVerification(t *testing.T) {
	source := filepath.Join(t.TempDir(), "source with spaces")
	if err := os.WriteFile(source, []byte("evidence"), 0600); err != nil {
		t.Fatal(err)
	}
	bundle := filepath.Join(t.TempDir(), "case")
	r := Request{Workflow: "evidence-collection", CaseID: "CASE-1", Operator: "analyst", Artifacts: []string{source}}
	m, err := Run(context.Background(), r, bundle, nil)
	if err != nil || m.Status != "complete" {
		t.Fatalf("%+v %v", m, err)
	}
	if _, err := Verify(bundle); err != nil {
		t.Fatal(err)
	}
	if _, err := Run(context.Background(), r, bundle, nil); err == nil {
		t.Fatal("overwrote bundle")
	}
	if err := os.WriteFile(filepath.Join(bundle, m.Steps[0].File), []byte("tampered"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(bundle); err == nil {
		t.Fatal("accepted changed evidence")
	}
}

func TestScopeAndFailures(t *testing.T) {
	for _, r := range []Request{{Workflow: "unknown"}, {Workflow: "evidence-collection"}, {Workflow: "baseline-assurance", Artifacts: []string{"/tmp/a"}}} {
		if _, err := Plan(r); err == nil {
			t.Fatalf("accepted %+v", r)
		}
	}
	source := filepath.Join(t.TempDir(), "source")
	os.WriteFile(source, []byte("x"), 0600)
	link := source + "-link"
	if err := os.Symlink(source, link); err != nil {
		t.Skip(err)
	}
	r := Request{Workflow: "evidence-collection", CaseID: "one", Operator: "two", Artifacts: []string{link}}
	m, err := Run(context.Background(), r, filepath.Join(t.TempDir(), "bundle"), nil)
	if err != nil || m.Status != "partial" || m.Steps[0].Error == "" {
		t.Fatalf("%+v %v", m, err)
	}
}

func TestBaselineRejectsFalseSuccess(t *testing.T) {
	for _, output := range []string{`{}`, `{"schema_version":1,"tool":"wrong","status":"complete","inventory":[],"findings":[],"errors":[]}`, `not json`} {
		m, err := Run(context.Background(), Request{Workflow: "baseline-assurance"}, filepath.Join(t.TempDir(), "run"), func(context.Context, string) ([]byte, error) { return []byte(output), nil })
		if err != nil || m.Status != "partial" {
			t.Fatalf("%+v %v", m, err)
		}
	}
}

func TestCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	m, err := Run(ctx, Request{Workflow: "baseline-assurance"}, filepath.Join(t.TempDir(), "run"), func(context.Context, string) ([]byte, error) { t.Fatal("executed after cancellation"); return nil, nil })
	if err != nil || m.Status != "cancelled" {
		t.Fatalf("%+v %v", m, err)
	}
}

func TestCompleteBaselineWithFindingsAndPartial(t *testing.T) {
	for _, status := range []string{"complete", "partial"} {
		m, err := Run(context.Background(), Request{Workflow: "baseline-assurance"}, filepath.Join(t.TempDir(), "bundle"), func(_ context.Context, tool string) ([]byte, error) {
			return []byte(fmt.Sprintf(`{"schema_version":1,"tool":%q,"status":%q,"inventory":[],"findings":[{"severity":"high"}],"errors":[]}`, tool, status)), nil
		})
		if err != nil || m.Status != status || m.Steps[0].Findings != 1 {
			t.Fatalf("%+v %v", m, err)
		}
	}
}
func TestConfinementAndLimits(t *testing.T) {
	root := t.TempDir()
	outside := filepath.Join(t.TempDir(), "outside")
	os.WriteFile(outside, []byte("secret"), 0600)
	r := Request{Workflow: "evidence-collection", CaseID: "case", Operator: "analyst", Artifacts: []string{outside}, SourceRoot: root}
	if _, err := Plan(r); err == nil {
		t.Fatal("accepted outside source")
	}
	link := filepath.Join(root, "link")
	if err := os.Symlink(filepath.Dir(outside), link); err != nil {
		t.Skip(err)
	}
	r.Artifacts = []string{filepath.Join(link, "outside")}
	m, err := Run(context.Background(), r, filepath.Join(t.TempDir(), "bundle"), nil)
	if err != nil || m.Status != "partial" {
		t.Fatalf("symlink escape: %+v %v", m, err)
	}
	large := filepath.Join(root, "large")
	f, err := os.Create(large)
	if err != nil {
		t.Fatal(err)
	}
	f.Truncate(MaxArtifact + 1)
	f.Close()
	r.Artifacts = []string{large}
	m, err = Run(context.Background(), r, filepath.Join(t.TempDir(), "bundle"), nil)
	if err != nil || m.Status != "partial" {
		t.Fatalf("oversized: %+v %v", m, err)
	}
	r.Artifacts = []string{root}
	m, err = Run(context.Background(), r, filepath.Join(t.TempDir(), "bundle"), nil)
	if err != nil || m.Status != "partial" {
		t.Fatalf("directory: %+v %v", m, err)
	}
}
func TestMissingEvidenceAndIncompleteManifest(t *testing.T) {
	source := filepath.Join(t.TempDir(), "evidence")
	os.WriteFile(source, []byte("abc"), 0600)
	bundle := filepath.Join(t.TempDir(), "bundle")
	m, err := Run(context.Background(), Request{Workflow: "evidence-collection", CaseID: "case", Operator: "analyst", Artifacts: []string{source}}, bundle, nil)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" {
		dirInfo, _ := os.Stat(bundle)
		fileInfo, _ := os.Stat(filepath.Join(bundle, m.Steps[0].File))
		if dirInfo.Mode().Perm() != 0700 || fileInfo.Mode().Perm() != 0600 {
			t.Fatal("unprotected bundle")
		}
	}
	os.Remove(filepath.Join(bundle, m.Steps[0].File))
	if _, err := Verify(bundle); err == nil {
		t.Fatal("missing evidence verified")
	}
	m.Status = "running"
	root, err := os.OpenRoot(bundle)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	save(root, m)
	if _, err := Verify(bundle); err == nil {
		t.Fatal("interrupted run verified")
	}
}

func TestPersistenceFailureIsNotCompletion(t *testing.T) {
	bundle := filepath.Join(t.TempDir(), "bundle")
	_, err := Run(context.Background(), Request{Workflow: "baseline-assurance"}, bundle, func(_ context.Context, tool string) ([]byte, error) {
		// Simulate loss of the evidence destination while collection is active.
		if e := os.RemoveAll(bundle); e != nil {
			t.Fatal(e)
		}
		return []byte(fmt.Sprintf(`{"schema_version":1,"tool":%q,"status":"complete","inventory":[],"findings":[],"errors":[]}`, tool)), nil
	})
	if err == nil {
		t.Fatal("persistence failure reported success")
	}
}
func TestOversizedCollectorAndCancellationDuringCollection(t *testing.T) {
	m, err := Run(context.Background(), Request{Workflow: "baseline-assurance"}, filepath.Join(t.TempDir(), "large"), func(context.Context, string) ([]byte, error) { return make([]byte, MaxReport+1), nil })
	if err != nil || m.Status != "partial" || m.Steps[0].File != "" {
		t.Fatalf("%+v %v", m, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	m, err = Run(ctx, Request{Workflow: "baseline-assurance"}, filepath.Join(t.TempDir(), "cancelled"), func(stepCtx context.Context, _ string) ([]byte, error) {
		cancel()
		<-stepCtx.Done()
		return nil, stepCtx.Err()
	})
	if err != nil || m.Status != "cancelled" {
		t.Fatalf("%+v %v", m, err)
	}
}
