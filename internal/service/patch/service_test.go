package patch

import (
	"context"
	"errors"
	"github.com/afterdarksys/afterdark-darkd/internal/models"
	"github.com/afterdarksys/afterdark-darkd/internal/platform"
	"github.com/afterdarksys/afterdark-darkd/internal/storage"
	storejson "github.com/afterdarksys/afterdark-darkd/internal/storage/json"
	"testing"
	"time"
)

type fakePlatform struct {
	platform.Platform
	err error
}

func (p *fakePlatform) ListAvailablePatches(context.Context) ([]platform.Patch, error) {
	return []platform.Patch{{ID: "critical", Severity: platform.SeverityCritical}}, p.err
}
func (p *fakePlatform) ListInstalledPatches(context.Context) ([]platform.Patch, error) {
	return nil, nil
}
func TestStableDeadlinesAndFailure(t *testing.T) {
	ctx := context.Background()
	store := storejson.New()
	if err := store.Initialize(ctx, &storage.Config{Path: t.TempDir()}); err != nil {
		t.Fatal(err)
	}
	cfg := models.DefaultConfig().Services.PatchMonitor
	p := &fakePlatform{}
	s := New(&cfg, p, store, nil)
	s.firstObserved["critical"] = time.Now().Add(-48 * time.Hour)
	s.performScan(ctx)
	first := s.GetComplianceStatus()
	if !first.Valid || first.Compliant {
		t.Fatalf("%+v", first)
	}
	s.performScan(ctx)
	second := s.GetComplianceStatus()
	if !first.UrgentActions[0].DueBy.Equal(second.UrgentActions[0].DueBy) {
		t.Fatal("deadline moved")
	}
	var saved map[string]time.Time
	if err := store.Load(ctx, "patch_state", "first_observed", &saved); err != nil || !saved["critical"].Equal(s.firstObserved["critical"]) {
		t.Fatal("deadline not persisted", err)
	}
	p.err = errors.New("permission denied")
	s.performScan(ctx)
	if s.GetComplianceStatus().Valid || s.GetComplianceStatus().Compliant {
		t.Fatal("failed collection retained compliant result")
	}
}
