package events

import (
	"strings"
	"time"
)

// Threats: a DNS observation without a process start time is partial, and an
// empty or oversized name is an error row. The name is omitted from error rows
// so a rejected query cannot be treated as a normal lookup.

// DNSEvent builds the journal payload for one captured query. A PID without a
// start time stays partial. Both together are one observed process instance.
func DNSEvent(domain, qtype, method string, pid int, started time.Time) map[string]any {
	facts := map[string]any{}
	if method != "" && validToken(method) {
		facts["collection_method"] = method
	}
	payload := map[string]any{
		"collection_status": CollectionPartial,
		"facts":             facts,
	}
	if domain == "" || len(domain) > 253 || strings.ContainsAny(domain, " \t\r\n") {
		payload["collection_status"] = CollectionError
		facts["dns.rejected"] = "invalid_name"
		return payload
	}
	facts["dns.name"] = domain
	if qtype != "" && validToken(strings.ToLower(qtype)) {
		facts["dns.type"] = strings.ToUpper(qtype)
	}
	if pid > 0 {
		process := map[string]any{"pid": pid}
		facts["process.pid"] = pid
		if !started.IsZero() {
			stamp := started.UTC().Format(time.RFC3339Nano)
			process["start_time"] = stamp
			facts["process.start_time"] = stamp
			payload["collection_status"] = CollectionObserved
		}
		payload["entities"] = map[string]any{"process": process}
	}
	return payload
}

// CaptureUnavailable records that DNS capture did not start.
func CaptureUnavailable(method string) map[string]any {
	facts := map[string]any{"dns.capture": "unavailable"}
	if method != "" && validToken(method) {
		facts["collection_method"] = method
	}
	return map[string]any{"collection_status": CollectionUnavailable, "facts": facts}
}

func validToken(value string) bool {
	if value == "" || len(value) > 32 {
		return false
	}
	for _, r := range value {
		if (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') && (r < '0' || r > '9') && r != '_' && r != '-' {
			return false
		}
	}
	return true
}
