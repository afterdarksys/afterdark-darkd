package events

import (
	"strings"
	"testing"
	"time"
)

func TestDNSEventKeepsGapsVisible(t *testing.T) {
	partial := DNSEvent("example.com", "aaaa", "logs", 41, time.Time{})
	if partial["collection_status"] != CollectionPartial {
		t.Fatalf("attributed query without a start time looked complete: %#v", partial)
	}
	facts := partial["facts"].(map[string]any)
	if _, ok := facts["process.start_time"]; ok {
		t.Fatal("start time invented for a DNS query")
	}
	rejected := DNSEvent(" "+strings.Repeat("a", 300), "A", "logs", -1, time.Time{})
	if rejected["collection_status"] != CollectionError {
		t.Fatalf("oversized name stored as a lookup: %#v", rejected)
	}
	if _, ok := rejected["facts"].(map[string]any)["dns.name"]; ok {
		t.Fatal("rejected name was retained")
	}
	started := time.Date(2026, 9, 25, 1, 2, 3, 0, time.UTC)
	observed := DNSEvent("example.com", "A", "logs", 41, started)
	if observed["collection_status"] != CollectionObserved {
		t.Fatalf("process-attributed query stayed partial: %#v", observed)
	}
	if observed["facts"].(map[string]any)["process.start_time"] != started.Format(time.RFC3339Nano) {
		t.Fatalf("start time missing: %#v", observed["facts"])
	}
	down := CaptureUnavailable("pcap")
	if down["collection_status"] != CollectionUnavailable {
		t.Fatalf("failed capture looked active: %#v", down)
	}
}
