package esf

import (
	"path/filepath"
	"strings"
	"time"
)

// Threats: an auth exec of launchctl, systemctl, kill, pkill, or killall is
// denied when its argument vector is missing, truncated, or would stop the
// agent. Any other executable is allowed when the vector is incomplete, so a
// long compiler command is not treated as a stop. Enforced is set only after
// es_respond_auth_result succeeds. The decision does not cache a path.

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

// Decide fails closed on an auth exec it cannot read. A notify event that
// lacks an argument vector stays a partial observation and is not described
// as a block.
func Decide(obs ExecObservation) Decision {
	decision := Decision{Action: "unavailable", CollectionStatus: StatusUnavailable, EventType: "endpoint_security.unknown", Severity: "info"}
	switch obs.Kind {
	case "notify_exec", "auth_exec":
		decision.EventType = "endpoint_security.exec"
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
		return decision
	}
	if stopsAgent(obs.Path, obs.Args) {
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
	if observationComplete(obs) {
		decision.CollectionStatus = StatusObserved
	}
	return decision
}

// AuthAllows is the kernel answer. Only an explicit allow is allowed.
func AuthAllows(obs ExecObservation) bool {
	return Decide(obs).Action == "allow"
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

func isStopTool(path string) bool {
	switch strings.ToLower(filepath.Base(path)) {
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
	base := strings.ToLower(filepath.Base(path))
	protected := false
	for _, arg := range append([]string{base}, args...) {
		lower := strings.ToLower(arg)
		if strings.Contains(lower, "afterdark-darkd") || strings.Contains(lower, "com.afterdark.darkd") {
			protected = true
			break
		}
	}
	switch base {
	case "launchctl":
		return protected && hasVerb(args, "bootout", "kill", "unload", "disable", "remove")
	case "systemctl":
		return protected && hasVerb(args, "stop", "kill", "disable", "mask")
	case "kill", "pkill", "killall":
		return protected
	default:
		return false
	}
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
