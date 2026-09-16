package reporting

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"testing"
)

func TestReportsPreserveFailuresAndEscapeHTML(t *testing.T) {
	r := Report{Kind: "security", Complete: true}
	r.Add("<script>alert(1)</script>", map[string]string{"host": "<untrusted>"}, nil)
	r.Add("Compliance", nil, errors.New("service unavailable"))
	var out bytes.Buffer
	if err := Write(&out, "json", r); err != nil {
		t.Fatal(err)
	}
	var got Report
	if err := json.Unmarshal(out.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.Complete || got.Sections[1].Error != "service unavailable" {
		t.Fatalf("lost failure: %+v", got)
	}
	out.Reset()
	if err := Write(&out, "html", r); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out.String(), "<script>") || !strings.Contains(out.String(), "&lt;script&gt;") || !strings.Contains(out.String(), "Incomplete:") {
		t.Fatal(out.String())
	}
}

func TestPDFPaginationAndOffsets(t *testing.T) {
	r := Report{Kind: "security", Complete: true}
	for i := 0; i < 90; i++ {
		r.Add(fmt.Sprint(i), map[string]string{"value": "evidence (parentheses) \\ Unicode: café"}, nil)
	}
	var out bytes.Buffer
	if err := Write(&out, "pdf", r); err != nil {
		t.Fatal(err)
	}
	pdf := out.String()
	if !strings.HasPrefix(pdf, "%PDF-1.4\n") || !strings.HasSuffix(pdf, "%%EOF\n") {
		t.Fatal("invalid framing")
	}
	marker := strings.LastIndex(pdf, "startxref\n")
	offset, err := strconv.Atoi(strings.Split(pdf[marker+10:], "\n")[0])
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(pdf[offset:], "xref\n") {
		t.Fatal("incorrect xref pointer")
	}
	lines := strings.Split(pdf[offset:], "\n")
	var zero, count int
	if _, err := fmt.Sscanf(lines[1], "%d %d", &zero, &count); err != nil {
		t.Fatal(err)
	}
	for i := 1; i < count; i++ {
		pos, err := strconv.Atoi(strings.Fields(lines[i+2])[0])
		if err != nil {
			t.Fatal(err)
		}
		if !strings.HasPrefix(pdf[pos:], fmt.Sprintf("%d 0 obj\n", i)) {
			t.Fatalf("bad object offset %d", i)
		}
	}
	if strings.Count(pdf, "/Type /Page ") < 2 {
		t.Fatal("missing pagination")
	}
}

func TestWriteFailure(t *testing.T) {
	if err := Write(failingWriter{}, "html", Report{}); err == nil {
		t.Fatal("write error lost")
	}
	if err := Write(&bytes.Buffer{}, "invalid", Report{}); err == nil {
		t.Fatal("invalid format accepted")
	}
}

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, errors.New("disk full") }
