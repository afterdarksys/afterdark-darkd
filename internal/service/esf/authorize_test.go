package esf

import (
	"testing"
	"time"
)

func TestAuthExecWithoutArgsDeniesWithoutClaimingEnforcement(t *testing.T) {
	decision := Decide(ExecObservation{Kind: "auth_exec", Path: "/bin/launchctl", ArgsTruncated: true})
	if decision.Action != "deny" || decision.Enforced || decision.CollectionStatus != StatusPartial {
		t.Fatalf("truncated auth exec was not a fail-closed recommendation: %+v", decision)
	}
	answered := Decide(ExecObservation{Kind: "auth_exec", Path: "/bin/launchctl", ArgsTruncated: true, Responded: true})
	if !answered.Enforced || answered.Action != "deny" {
		t.Fatalf("answered auth denial lost enforcement: %+v", answered)
	}
}

func TestStopVerbIsVisibleAndNotifyCannotBlock(t *testing.T) {
	decision := Decide(ExecObservation{Kind: "notify_exec", Path: "/bin/launchctl", Args: []string{"bootout", "system/com.afterdark.darkd"}})
	if decision.Action != "deny" || decision.Enforced || decision.EventType != "endpoint_security.exec" {
		t.Fatalf("stop verb was not recorded as an unenforced denial: %+v", decision)
	}
	allow := Decide(ExecObservation{Kind: "notify_exec", Path: "/bin/launchctl", Args: []string{"print", "system"}})
	if allow.Action != "allow" || allow.Enforced {
		t.Fatalf("unrelated launchctl looked like a block: %+v", allow)
	}
}

func TestTruncatedOrdinaryExecIsAllowed(t *testing.T) {
	decision := Decide(ExecObservation{Kind: "auth_exec", Path: "/usr/bin/clang", ArgsTruncated: true, Responded: true, Started: time.Date(2026, 9, 25, 0, 0, 0, 0, time.UTC)})
	if decision.Action != "allow" || !decision.Enforced || decision.CollectionStatus != StatusPartial {
		t.Fatalf("ordinary truncated exec was blocked or marked complete: %+v", decision)
	}
	if AuthAllows(ExecObservation{Kind: "auth_exec", Path: ""}) {
		t.Fatal("auth exec with no path was allowed")
	}
}

func TestAnsweredStopWithStartTimeIsObserved(t *testing.T) {
	started := time.Date(2026, 9, 25, 1, 2, 3, 0, time.UTC)
	decision := Decide(ExecObservation{Kind: "auth_exec", Path: "/bin/launchctl", Args: []string{"bootout", "system/com.afterdark.darkd"}, Started: started, Responded: true})
	if decision.Action != "deny" || !decision.Enforced || decision.CollectionStatus != StatusObserved {
		t.Fatalf("answered stop was not an observed enforcement: %+v", decision)
	}
}

func TestUnknownMessageIsUnavailable(t *testing.T) {
	decision := Decide(ExecObservation{Kind: "", Path: "/bin/sh"})
	if decision.Action != "unavailable" || decision.CollectionStatus != StatusUnavailable || decision.Enforced {
		t.Fatalf("unknown message looked actionable: %+v", decision)
	}
	file := Decide(ExecObservation{Kind: "notify_unlink", Path: "/tmp/canary"})
	if file.EventType != "file.unlink" || file.Enforced || file.CollectionStatus != StatusPartial {
		t.Fatalf("unlink observation overclaimed: %+v", file)
	}
}
