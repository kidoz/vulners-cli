package report

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

// MarkdownReporter writes output as Markdown tables, suitable for
// GitHub Step Summaries, PR comments, and documentation.
type MarkdownReporter struct{}

type mdData struct {
	Target   string      `json:"target"`
	Findings []mdFinding `json:"findings"`
	Summary  mdSummary   `json:"summary"`
}

type mdFinding struct {
	VulnID       string  `json:"vulnID"`
	Severity     string  `json:"severity"`
	CVSS         float64 `json:"cvss"`
	ComponentRef string  `json:"componentRef"`
	Fix          string  `json:"fix"`
}

type mdSummary struct {
	ComponentCount int `json:"componentCount"`
	FindingCount   int `json:"findingCount"`
	Critical       int `json:"critical"`
	High           int `json:"high"`
	Medium         int `json:"medium"`
	Low            int `json:"low"`
}

func (r *MarkdownReporter) Write(w io.Writer, data any) error {
	raw, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("marshaling data for markdown: %w", err)
	}

	// Try scan-structured data first.
	var d mdData
	if err := json.Unmarshal(raw, &d); err == nil && d.Target != "" {
		return writeScanMarkdown(w, d)
	}

	// Fall back to generic rendering.
	var generic any
	if err := json.Unmarshal(raw, &generic); err != nil {
		return fmt.Errorf("unmarshaling for markdown: %w", err)
	}

	return writeGenericMarkdown(w, generic)
}

func writeScanMarkdown(w io.Writer, d mdData) error {
	_, _ = fmt.Fprintf(w, "# Scan Report: %s\n\n", escapeMD(d.Target))

	// Summary table.
	_, _ = fmt.Fprint(w, "## Summary\n\n")
	_, _ = fmt.Fprintln(w, "| Metric | Count |")
	_, _ = fmt.Fprintln(w, "|--------|-------|")
	_, _ = fmt.Fprintf(w, "| Components | %d |\n", d.Summary.ComponentCount)
	_, _ = fmt.Fprintf(w, "| Findings | %d |\n", d.Summary.FindingCount)
	_, _ = fmt.Fprintf(w, "| Critical | %d |\n", d.Summary.Critical)
	_, _ = fmt.Fprintf(w, "| High | %d |\n", d.Summary.High)
	_, _ = fmt.Fprintf(w, "| Medium | %d |\n", d.Summary.Medium)
	_, _ = fmt.Fprintf(w, "| Low | %d |\n", d.Summary.Low)

	// Findings table.
	_, _ = fmt.Fprint(w, "\n## Findings\n\n")
	if len(d.Findings) == 0 {
		_, _ = fmt.Fprintln(w, "No findings.")
		return nil
	}

	_, _ = fmt.Fprintln(w, "| Severity | ID | Component | CVSS | Fix |")
	_, _ = fmt.Fprintln(w, "|----------|----|-----------|------|-----|")
	for _, f := range d.Findings {
		_, _ = fmt.Fprintf(w, "| %s | %s | %s | %.1f | %s |\n",
			escapeMD(strings.ToUpper(f.Severity)),
			escapeMD(f.VulnID),
			escapeMD(f.ComponentRef),
			f.CVSS,
			escapeMD(f.Fix),
		)
	}

	return nil
}

func writeGenericMarkdown(w io.Writer, data any) error {
	switch v := data.(type) {
	case []any:
		return writeSliceMarkdown(w, v)
	case map[string]any:
		writeMapMarkdown(w, v)
	default:
		_, _ = fmt.Fprintf(w, "%v\n", data)
	}
	return nil
}

func writeSliceMarkdown(w io.Writer, items []any) error {
	if len(items) == 0 {
		_, _ = fmt.Fprintln(w, "(no results)")
		return nil
	}

	first, ok := items[0].(map[string]any)
	if !ok {
		for _, item := range items {
			_, _ = fmt.Fprintf(w, "%v\n", item)
		}
		return nil
	}

	keys := sortedKeys(first)

	// Header row.
	_, _ = fmt.Fprintf(w, "| %s |\n", strings.Join(keys, " | "))
	// Separator row.
	seps := make([]string, len(keys))
	for i := range seps {
		seps[i] = "---"
	}
	_, _ = fmt.Fprintf(w, "| %s |\n", strings.Join(seps, " | "))

	// Data rows.
	for _, item := range items {
		row, ok := item.(map[string]any)
		if !ok {
			continue
		}
		vals := make([]string, len(keys))
		for i, k := range keys {
			vals[i] = escapeMD(truncate(fmt.Sprintf("%v", row[k]), 80))
		}
		_, _ = fmt.Fprintf(w, "| %s |\n", strings.Join(vals, " | "))
	}

	return nil
}

func writeMapMarkdown(w io.Writer, m map[string]any) {
	_, _ = fmt.Fprintln(w, "| Key | Value |")
	_, _ = fmt.Fprintln(w, "|-----|-------|")
	for _, k := range sortedKeys(m) {
		_, _ = fmt.Fprintf(w, "| %s | %s |\n",
			escapeMD(k),
			escapeMD(truncate(fmt.Sprintf("%v", m[k]), 120)),
		)
	}
}

// escapeMD escapes pipe characters in markdown table cells.
func escapeMD(s string) string {
	return strings.ReplaceAll(s, "|", "\\|")
}
