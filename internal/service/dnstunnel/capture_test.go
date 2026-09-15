package dnstunnel

import (
	"context"
	"go.uber.org/zap"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestTailAfterEOFAndRotation(t *testing.T) {
	p := filepath.Join(t.TempDir(), "dns.log")
	if err := os.WriteFile(p, nil, 0600); err != nil {
		t.Fatal(err)
	}
	c, _ := NewLogCapture(zap.NewNop())
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go c.tailLog(ctx, p)
	time.Sleep(300 * time.Millisecond)
	appendLine := func(line string) {
		t.Helper()
		f, err := os.OpenFile(p, os.O_APPEND|os.O_WRONLY, 0600)
		if err != nil {
			t.Fatal(err)
		}
		_, err = f.WriteString(line)
		f.Close()
		if err != nil {
			t.Fatal(err)
		}
	}
	expect := func(domain, kind string) {
		t.Helper()
		select {
		case q := <-c.Queries():
			if q.Domain != domain || q.RecordType != kind {
				t.Fatalf("%+v", q)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("query lost after EOF/rotation")
		}
	}
	appendLine("query[A] example.com from 127.0.0.1\n")
	expect("example.com", "A")
	if err := os.Rename(p, p+".old"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte("client 127.0.0.1 query: bind.example. IN AAAA\n"), 0600); err != nil {
		t.Fatal(err)
	}
	expect("bind.example", "AAAA")
}
