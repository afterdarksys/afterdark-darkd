// Package reporting renders collected evidence without inventing missing data.
package reporting

import (
	"bytes"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"strings"
	"time"
)

type Section struct {
	Name  string          `json:"name"`
	Data  json.RawMessage `json:"data,omitempty"`
	Error string          `json:"error,omitempty"`
}
type Report struct {
	GeneratedAt time.Time `json:"generated_at"`
	Kind        string    `json:"kind"`
	Complete    bool      `json:"complete"`
	Sections    []Section `json:"sections"`
}

func (r *Report) Add(name string, value any, err error) {
	s := Section{Name: name}
	if err == nil {
		s.Data, err = json.MarshalIndent(value, "", "  ")
	}
	if err != nil {
		s.Error = err.Error()
		r.Complete = false
	}
	r.Sections = append(r.Sections, s)
}

var page = template.Must(template.New("report").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>AfterDark Security Report</title>
<style>body{font:16px system-ui;max-width:1000px;margin:40px auto;padding:0 24px;color:#17202a}pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#f3f5f7;padding:16px}.error{color:#a21d26}@media print{section{break-inside:avoid}body{margin:0}}</style></head>
<body><h1>AfterDark {{.Kind}} Report</h1><p>Generated: {{.GeneratedAt}}</p>
{{if .Complete}}<p>All requested evidence collected.</p>{{else}}<p class="error">Incomplete: some evidence could not be collected. Missing evidence is not a passing security result.</p>{{end}}
{{range .Sections}}<section><h2>{{.Name}}</h2>{{if .Error}}<p class="error">Unavailable: {{.Error}}</p>{{else}}<pre>{{printf "%s" .Data}}</pre>{{end}}</section>{{end}}
</body></html>`))

func Write(w io.Writer, format string, r Report) error {
	switch format {
	case "json":
		e := json.NewEncoder(w)
		e.SetIndent("", "  ")
		return e.Encode(r)
	case "html":
		return page.Execute(w, r)
	case "pdf":
		return writePDF(w, r)
	default:
		return fmt.Errorf("unsupported report format %q (use json, html, pdf)", format)
	}
}

// PDF uses the built-in Courier font. Unicode is represented with JSON escapes
// so the complete evidence remains readable with a portable standard PDF font.
func writePDF(w io.Writer, r Report) error {
	data, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}
	var ascii strings.Builder
	for _, c := range string(data) {
		if c > 126 {
			fmt.Fprintf(&ascii, "\\u%04x", c)
		} else {
			ascii.WriteRune(c)
		}
	}
	var lines []string
	for _, line := range strings.Split(ascii.String(), "\n") {
		for len(line) > 95 {
			lines = append(lines, line[:95])
			line = line[95:]
		}
		lines = append(lines, line)
	}
	pages := (len(lines) + 59) / 60
	objects := []string{"<< /Type /Catalog /Pages 2 0 R >>", "", "<< /Type /Font /Subtype /Type1 /BaseFont /Courier >>"}
	var kids []string
	for i := 0; i < pages; i++ {
		pageID := len(objects) + 1
		streamID := pageID + 1
		kids = append(kids, fmt.Sprintf("%d 0 R", pageID))
		objects = append(objects, fmt.Sprintf("<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 3 0 R >> >> /Contents %d 0 R >>", streamID))
		var stream strings.Builder
		stream.WriteString("BT /F1 9 Tf 36 756 Td 12 TL\n")
		end := (i + 1) * 60
		if end > len(lines) {
			end = len(lines)
		}
		escape := strings.NewReplacer("\\", "\\\\", "(", "\\(", ")", "\\)", "\r", "")
		for _, line := range lines[i*60 : end] {
			fmt.Fprintf(&stream, "(%s) Tj T*\n", escape.Replace(line))
		}
		stream.WriteString("ET\n")
		objects = append(objects, fmt.Sprintf("<< /Length %d >>\nstream\n%sendstream", stream.Len(), stream.String()))
	}
	objects[1] = fmt.Sprintf("<< /Type /Pages /Count %d /Kids [%s] >>", pages, strings.Join(kids, " "))
	var out bytes.Buffer
	out.WriteString("%PDF-1.4\n")
	offsets := []int{0}
	for i, object := range objects {
		offsets = append(offsets, out.Len())
		fmt.Fprintf(&out, "%d 0 obj\n%s\nendobj\n", i+1, object)
	}
	xref := out.Len()
	fmt.Fprintf(&out, "xref\n0 %d\n0000000000 65535 f \n", len(offsets))
	for _, offset := range offsets[1:] {
		fmt.Fprintf(&out, "%010d 00000 n \n", offset)
	}
	fmt.Fprintf(&out, "trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n", len(offsets), xref)
	_, err = w.Write(out.Bytes())
	return err
}
