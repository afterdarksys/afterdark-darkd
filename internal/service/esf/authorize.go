package esf

import (
	"strings"
	"time"
)

// Threats: stop protection has two layers.
//
// AUTH_SIGNAL is the enforcing layer. A signal aimed at this process is denied
// when its default action would terminate or stop it: HUP INT QUIT ILL TRAP
// ABRT EMT FPE KILL BUS SEGV SYS PIPE ALRM TERM STOP TSTP TTIN TTOU XCPU XFSZ
// VTALRM PROF USR1 USR2. The Go runtime currently catches some of these
// (USR1/2, ALRM, PIPE, a kill-sent SEGV), but cgo code, signal.Reset, or an
// early delivery before signal.Notify can restore the default, so the list
// follows the default action and not today's handlers. HUP is the reload
// signal; reload stays reachable through `launchctl kill HUP`, which arrives
// from launchd. Signals that cannot stop the process (0, URG, CONT, CHLD, IO,
// WINCH, INFO) are allowed. Senders launchd (pid 1), the kernel (pid 0), and
// this process are always allowed so shutdown, reboot, and upgrade work. ES
// does not raise the event for a process signalling itself.
//
// The argv exec check is telemetry plus a best-effort deny. An auth exec of
// launchctl, systemctl, kill, pkill, or killall is denied when its argument
// vector is missing, truncated, or names the agent exactly (labels
// com.afterdark.darkd and com.afterdarksys.darkd, unit or binary
// afterdark-darkd, or their plists) with a stop verb. Sibling components
// (afterdark-darkd-netguard, com.afterdark.darkd.netguard,
// com.afterdarksys.darkd.netguard, afterdark-darkd-contextacld) stay
// stoppable. Any other executable is allowed when its vector is incomplete.
//
// The sanctioned stop path is a signed control token (internal/control). A
// verified token opens a 120 second maintenance window; while it is open an
// exec that names the agent with a stop verb, and a stopping signal to this
// process, are allowed. A missing or truncated argument vector is still
// denied. The window is not bound to the peer that presented the token.
//
// On an internal error (Go panic, no authorizer, failed copy) the C bridge
// allows an exec unless its basename is a stop tool, and allows a signal. The
// journal records the answer actually sent; Enforced is set only after
// es_respond_auth_result succeeds. No decision is cached.
//
// Not covered: launchd-delegated signals (`launchctl stop`, `kickstart -k`,
// `bootout`) arrive from pid 1 and are allowed; only the argv check sees the
// request, and a renamed launchctl or an XPC client talking to launchd directly
// passes it. The ES instigator field (message v9+) is not yet used. Deleting or
// renaming the binary or plist (AUTH_UNLINK/RENAME) is not protected; that
// needs an installer allowlist. A root process can still unload the ES
// extension or reboot.

// ExecObservation is the portion of an Endpoint Security message the decision
// uses. Args are not retained in the journal.
type ExecObservation struct {
	Kind          string
	Path          string
	Args          []string
	ArgsTruncated bool
	PID           int
	PPID          int
	Started       time.Time
	Responded     bool
	// Answer is the auth result the bridge sent ("allow" or "deny"). When set
	// it is recorded instead of a recomputed decision.
	Answer    string
	Fallback  bool
	TargetPID int
	Signal    int
	// Maintenance is true when a verified control token's window was open at
	// decision time.
	Maintenance bool
}

// Decision is stored with the observation. Enforced is true only after the
// kernel was given this action.
type Decision struct {
	Action           string
	Enforced         bool
	Reason           string
	CollectionStatus string
	EventType        string
	Severity         string
}

// Decide fails closed on an auth exec of a stop tool it cannot read. A notify
// event that lacks an argument vector stays a partial observation and is not
// described as a block.
func Decide(obs ExecObservation) Decision {
	decision := Decision{Action: "unavailable", CollectionStatus: StatusUnavailable, EventType: "endpoint_security.unknown", Severity: "info"}
	switch obs.Kind {
	case "notify_exec", "auth_exec":
		decision.EventType = "endpoint_security.exec"
	case "auth_signal":
		decision.EventType = "endpoint_security.signal"
		return recordSignal(obs, decision)
	case "notify_fork":
		decision.EventType = "endpoint_security.fork"
	case "notify_exit":
		decision.EventType = "endpoint_security.exit"
	case "notify_write":
		decision.EventType = "file.write"
	case "notify_unlink":
		decision.EventType = "file.unlink"
	default:
		decision.Reason = "endpoint security message was not recognized"
		return decision
	}
	if obs.Path == "" {
		decision.Reason = "endpoint security message had no path"
		decision.CollectionStatus = StatusPartial
		if obs.Kind == "auth_exec" && obs.Answer != "" {
			decision.Action = obs.Answer
			decision.Enforced = obs.Responded
			decision.Reason = "auth exec path was unavailable; fallback answer sent"
			if obs.Answer == "deny" {
				decision.Severity = "warning"
			}
		}
		return decision
	}
	decision.CollectionStatus = StatusPartial
	decision.Action = "allow"
	decision.Reason = "event recorded"
	if obs.Kind == "notify_write" || obs.Kind == "notify_unlink" || obs.Kind == "notify_fork" || obs.Kind == "notify_exit" {
		if observationComplete(obs) {
			decision.CollectionStatus = StatusObserved
		}
		return decision
	}
	if obs.Kind == "auth_exec" && (obs.ArgsTruncated || len(obs.Args) == 0) && isStopTool(obs.Path) {
		decision.Action = "deny"
		decision.Severity = "warning"
		decision.Reason = "auth exec argument vector was missing or truncated"
		decision.Enforced = obs.Responded
	} else if stopsAgent(obs.Path, obs.Args) && obs.Maintenance {
		decision.Reason = "exec stops the endpoint agent during a signed maintenance window"
		decision.Enforced = obs.Responded && obs.Kind == "auth_exec"
	} else if stopsAgent(obs.Path, obs.Args) {
		decision.Action = "deny"
		decision.Severity = "warning"
		decision.Reason = "exec would stop the endpoint agent"
		decision.Enforced = obs.Responded && obs.Kind == "auth_exec"
		if !decision.Enforced {
			decision.Reason = "exec would stop the endpoint agent; notify subscription cannot block it"
		}
	} else if obs.Kind == "auth_exec" && obs.Responded {
		decision.Enforced = true
		decision.Reason = "auth exec was answered"
	}
	if obs.Kind == "auth_exec" && obs.Answer != "" {
		if obs.Fallback {
			decision.Reason = "authorizer unavailable; basename fallback answered " + obs.Answer
		} else if obs.Answer != decision.Action {
			decision.Reason = "recorded the answer sent, which differs from the recomputed " + decision.Action
		}
		decision.Action = obs.Answer
		decision.Enforced = obs.Responded
		if obs.Answer == "deny" {
			decision.Severity = "warning"
		}
	}
	if observationComplete(obs) {
		decision.CollectionStatus = StatusObserved
	}
	return decision
}

// recordSignal describes an auth signal the bridge answered. The bridge only
// delivers denials and fallback answers.
func recordSignal(obs ExecObservation, decision Decision) Decision {
	decision.CollectionStatus = StatusPartial
	if obs.Answer == "" {
		decision.Reason = "auth signal answer was not reported"
		return decision
	}
	decision.Action = obs.Answer
	decision.Enforced = obs.Responded
	switch {
	case obs.Fallback:
		decision.Reason = "signal authorizer unavailable; allowed"
	case obs.Answer == "deny":
		decision.Reason = "signal would stop the endpoint agent"
	default:
		decision.Reason = "signal was answered"
	}
	if obs.Answer == "deny" {
		decision.Severity = "warning"
	}
	if obs.Path != "" && !obs.Started.IsZero() && obs.Responded {
		decision.CollectionStatus = StatusObserved
	}
	return decision
}

// AuthAllows is the kernel answer. Only an explicit allow is allowed.
func AuthAllows(obs ExecObservation) bool {
	return Decide(obs).Action == "allow"
}

// Darwin signal numbers. Endpoint Security only exists on darwin, and these
// differ on linux, so they are not taken from syscall.
const (
	sigHUP    = 1
	sigINT    = 2
	sigQUIT   = 3
	sigILL    = 4
	sigTRAP   = 5
	sigABRT   = 6
	sigEMT    = 7
	sigFPE    = 8
	sigKILL   = 9
	sigBUS    = 10
	sigSEGV   = 11
	sigSYS    = 12
	sigPIPE   = 13
	sigALRM   = 14
	sigTERM   = 15
	sigSTOP   = 17
	sigTSTP   = 18
	sigTTIN   = 21
	sigTTOU   = 22
	sigXCPU   = 24
	sigXFSZ   = 25
	sigVTALRM = 26
	sigPROF   = 27
	sigUSR1   = 30
	sigUSR2   = 31
)

// DecideSignal reports whether a signal may be delivered. Only a stopping or
// terminating signal from an unexempt sender to this process is denied, and
// not while a signed maintenance window is open.
func DecideSignal(senderPID, targetPID, selfPID, sig int, maintenance bool) bool {
	if targetPID != selfPID || selfPID <= 0 || maintenance {
		return true
	}
	if senderPID == 0 || senderPID == 1 || senderPID == selfPID {
		return true
	}
	switch sig {
	case sigHUP, sigINT, sigQUIT, sigILL, sigTRAP, sigABRT, sigEMT, sigFPE, sigKILL,
		sigBUS, sigSEGV, sigSYS, sigPIPE, sigALRM, sigTERM, sigSTOP, sigTSTP, sigTTIN,
		sigTTOU, sigXCPU, sigXFSZ, sigVTALRM, sigPROF, sigUSR1, sigUSR2:
		return false
	default:
		return true
	}
}

func observationComplete(obs ExecObservation) bool {
	if obs.Path == "" || obs.Started.IsZero() {
		return false
	}
	if obs.Kind == "auth_exec" && !obs.Responded {
		return false
	}
	if (obs.Kind == "notify_exec" || obs.Kind == "auth_exec") && (obs.ArgsTruncated || (obs.Kind == "auth_exec" && len(obs.Args) == 0)) {
		return false
	}
	return true
}

// isStopTool mirrors is_stop_tool in client_esf.c: case-insensitive match of
// the text after the last slash.
func isStopTool(path string) bool {
	switch strings.ToLower(path[strings.LastIndexByte(path, '/')+1:]) {
	case "launchctl", "systemctl", "kill", "pkill", "killall":
		return true
	default:
		return false
	}
}

const (
	StatusObserved    = "observed"
	StatusPartial     = "partial"
	StatusUnavailable = "unavailable"
)

func stopsAgent(path string, args []string) bool {
	base := strings.ToLower(path[strings.LastIndexByte(path, '/')+1:])
	protected := false
	for _, arg := range args {
		if namesAgent(arg) {
			protected = true
			break
		}
	}
	switch base {
	case "launchctl":
		return protected && hasVerb(args, "bootout", "kill", "unload", "disable", "remove", "stop", "kickstart")
	case "systemctl":
		return protected && hasVerb(args, "stop", "kill", "disable", "mask")
	case "kill", "pkill", "killall":
		return protected
	default:
		return false
	}
}

// namesAgent matches the agent's label, unit, binary, or plist exactly. Each
// whitespace field is reduced to the text after its last slash, so
// system/com.afterdarksys.darkd and /usr/local/bin/afterdark-darkd match while
// com.afterdarksys.darkd.netguard and afterdark-darkd-contextacld do not.
func namesAgent(arg string) bool {
	for _, field := range strings.Fields(arg) {
		switch strings.ToLower(field[strings.LastIndexByte(field, '/')+1:]) {
		case "com.afterdark.darkd", "com.afterdark.darkd.plist", "com.afterdarksys.darkd", "com.afterdarksys.darkd.plist",
			"afterdark-darkd", "afterdark-darkd.service":
			return true
		}
	}
	return false
}

func hasVerb(args []string, verbs ...string) bool {
	for _, arg := range args {
		lower := strings.ToLower(arg)
		for _, verb := range verbs {
			if lower == verb {
				return true
			}
		}
	}
	return false
}
