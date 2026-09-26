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

func authExec(path string, args ...string) ExecObservation {
	return ExecObservation{Kind: "auth_exec", Path: path, Args: append([]string{path}, args...), Responded: true}
}

func TestStopVerbsAndExactNamesAreDenied(t *testing.T) {
	for _, obs := range []ExecObservation{
		authExec("/bin/launchctl", "stop", "com.afterdark.darkd"),
		authExec("/bin/launchctl", "kickstart", "-k", "system/com.afterdark.darkd"),
		authExec("/bin/launchctl", "unload", "/Library/LaunchDaemons/com.afterdark.darkd.plist"),
		authExec("/usr/bin/pkill", "-f", "/usr/local/bin/afterdark-darkd"),
		authExec("/usr/bin/killall", "afterdark-darkd"),
		authExec("/bin/launchctl", "kickstart", "-k", "system/com.afterdarksys.darkd"),
		authExec("/bin/launchctl", "unload", "/Library/LaunchDaemons/com.afterdarksys.darkd.plist"),
		authExec("/bin/launchctl", "bootout", "system/com.afterdarksys.darkd"),
		authExec("/bin/launchctl", "stop", "com.afterdarksys.darkd"),
		authExec("/bin/launchctl", "disable", "system/COM.AFTERDARKSYS.DARKD"),
	} {
		if d := Decide(obs); d.Action != "deny" || !d.Enforced {
			t.Fatalf("stop of the agent was allowed: %v -> %+v", obs.Args, d)
		}
	}
}

func TestSiblingComponentsStayStoppable(t *testing.T) {
	for _, obs := range []ExecObservation{
		authExec("/bin/launchctl", "bootout", "system/com.afterdark.darkd.netguard"),
		authExec("/usr/bin/pkill", "-f", "afterdark-darkd-contextacld"),
		authExec("/usr/bin/killall", "afterdark-darkd-netguard"),
		authExec("/bin/launchctl", "print", "system/com.afterdark.darkd"),
		authExec("/bin/launchctl", "bootout", "system/com.afterdarksys.darkd.netguard"),
		authExec("/bin/launchctl", "unload", "/Library/LaunchDaemons/com.afterdarksys.darkd.netguard.plist"),
		authExec("/bin/launchctl", "kickstart", "-k", "system/com.afterdarksys.darkd-contextacld"),
		authExec("/bin/launchctl", "print", "system/com.afterdarksys.darkd"),
	} {
		if d := Decide(obs); d.Action != "allow" {
			t.Fatalf("sibling or read-only command was denied: %v -> %+v", obs.Args, d)
		}
	}
}

func TestLongKillWithinLimitIsAllowedAndTruncatedStopToolDenied(t *testing.T) {
	pids := make([]string, 20)
	for i := range pids {
		pids[i] = "4" + string(rune('0'+i%10))
	}
	if !AuthAllows(authExec("/bin/kill", pids...)) {
		t.Fatal("kill with 20 pids was denied")
	}
	clang := authExec("/usr/bin/clang", "-c", "x.c")
	clang.ArgsTruncated = true
	if !AuthAllows(clang) {
		t.Fatal("truncated clang was denied")
	}
	killall := authExec("/usr/bin/killall", "foo")
	killall.ArgsTruncated = true
	if AuthAllows(killall) {
		t.Fatal("truncated killall was allowed")
	}
}

func TestDecideSignal(t *testing.T) {
	const self = 500
	cases := []struct {
		name                string
		sender, target, sig int
		allow               bool
	}{
		{"launchd", 1, self, sigKILL, true},
		{"kernel", 0, self, sigTERM, true},
		{"self", self, self, sigKILL, true},
		{"other kill", 777, self, sigKILL, false},
		{"other term", 777, self, sigTERM, false},
		{"other stop", 777, self, sigSTOP, false},
		{"other hup", 777, self, sigHUP, false},
		{"other usr1", 777, self, sigUSR1, false},
		{"other term elsewhere", 777, 900, sigTERM, true},
		{"info", 777, self, 29, true},
		{"winch", 777, self, 28, true},
		{"cont", 777, self, 19, true},
		{"probe", 777, self, 0, true},
	}
	for _, c := range cases {
		if got := DecideSignal(c.sender, c.target, self, c.sig, false); got != c.allow {
			t.Fatalf("%s: DecideSignal=%v want %v", c.name, got, c.allow)
		}
	}
	if !DecideSignal(777, 0, 0, sigKILL, false) {
		t.Fatal("unknown self pid denied a signal")
	}
}

func TestFallbackBasenameMatchesStopToolsOnly(t *testing.T) {
	for _, p := range []string{"/bin/launchctl", "/bin/kill", "/usr/bin/pkill", "/usr/bin/KILLALL", "systemctl"} {
		if !isStopTool(p) {
			t.Fatalf("%s not treated as a stop tool", p)
		}
	}
	for _, p := range []string{"/usr/bin/clang", "/bin/sh", "/tmp/killer", "/tmp/kill/x", "", "/"} {
		if isStopTool(p) {
			t.Fatalf("%s treated as a stop tool", p)
		}
	}
}

func TestRecordedAnswerIsTheOneSent(t *testing.T) {
	fallback := Decide(ExecObservation{Kind: "auth_exec", Path: "/bin/launchctl", Args: []string{"launchctl", "print"}, Responded: true, Answer: "deny", Fallback: true})
	if fallback.Action != "deny" || !fallback.Enforced || fallback.Severity != "warning" {
		t.Fatalf("fallback denial not recorded as sent: %+v", fallback)
	}
	noPath := Decide(ExecObservation{Kind: "auth_exec", Responded: true, Answer: "deny", Fallback: true})
	if noPath.Action != "deny" || !noPath.Enforced || noPath.Reason == "" || noPath.CollectionStatus != StatusPartial {
		t.Fatalf("denied exec without a path was not journaled: %+v", noPath)
	}
	unanswered := Decide(ExecObservation{Kind: "auth_exec", Path: "/bin/sh", Args: []string{"sh"}, Answer: "allow"})
	if unanswered.Enforced {
		t.Fatalf("failed respond claimed enforcement: %+v", unanswered)
	}
	sig := Decide(ExecObservation{Kind: "auth_signal", Path: "/bin/kill", Responded: true, Answer: "deny", TargetPID: 500, Signal: sigKILL})
	if sig.EventType != "endpoint_security.signal" || sig.Action != "deny" || !sig.Enforced {
		t.Fatalf("signal denial not recorded: %+v", sig)
	}
	lost := Decide(ExecObservation{Kind: "auth_signal", Path: "/bin/kill", Answer: "deny"})
	if lost.Enforced {
		t.Fatalf("unanswered signal claimed enforcement: %+v", lost)
	}
}

func maintenance(obs ExecObservation) ExecObservation {
	obs.Maintenance = true
	return obs
}

func TestMaintenanceWindowAllowsSanctionedStop(t *testing.T) {
	for _, obs := range []ExecObservation{
		authExec("/bin/launchctl", "unload", "/Library/LaunchDaemons/com.afterdarksys.darkd.plist"),
		authExec("/bin/launchctl", "kickstart", "-k", "system/com.afterdarksys.darkd"),
		authExec("/bin/launchctl", "bootout", "system/com.afterdark.darkd"),
		authExec("/usr/bin/pkill", "-f", "/usr/local/bin/afterdark-darkd"),
		authExec("/usr/bin/killall", "afterdark-darkd"),
	} {
		if AuthAllows(obs) {
			t.Fatalf("stop allowed with the window closed: %v", obs.Args)
		}
		d := Decide(maintenance(obs))
		if d.Action != "allow" || !d.Enforced || d.Severity != "info" {
			t.Fatalf("stop denied during the window: %v -> %+v", obs.Args, d)
		}
	}
	// The window does not relax the fail-closed rule for an unreadable vector.
	truncated := authExec("/bin/launchctl", "unload", "com.afterdarksys.darkd")
	truncated.ArgsTruncated = true
	if AuthAllows(maintenance(truncated)) {
		t.Fatal("truncated launchctl allowed during the window")
	}
	if AuthAllows(maintenance(ExecObservation{Kind: "auth_exec", Path: "/bin/launchctl", Responded: true})) {
		t.Fatal("launchctl without argv allowed during the window")
	}
	// A notify event during the window is not described as a block.
	notify := Decide(maintenance(ExecObservation{Kind: "notify_exec", Path: "/bin/launchctl", Args: []string{"launchctl", "stop", "com.afterdarksys.darkd"}}))
	if notify.Action != "allow" || notify.Enforced {
		t.Fatalf("notify during window: %+v", notify)
	}
}

func TestMaintenanceWindowAllowsStoppingSignals(t *testing.T) {
	const self = 500
	for _, sig := range []int{sigTERM, sigKILL, sigINT, sigSTOP, sigHUP, sigQUIT} {
		if DecideSignal(777, self, self, sig, false) {
			t.Fatalf("signal %d allowed with the window closed", sig)
		}
		if !DecideSignal(777, self, self, sig, true) {
			t.Fatalf("signal %d denied during the window", sig)
		}
	}
}
