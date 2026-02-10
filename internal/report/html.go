package report

import (
	"embed"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
)

//go:embed templates/report.html.tmpl
var htmlTemplates embed.FS

// HTMLReporter writes output as a self-contained HTML report.
type HTMLReporter struct{}

type htmlData struct {
	SchemaVersion string        `json:"schemaVersion"`
	Target        string        `json:"target"`
	Findings      []htmlFinding `json:"findings"`
	Summary       htmlSummary   `json:"summary"`
}

type htmlFinding struct {
	VulnID       string  `json:"vulnID"`
	Severity     string  `json:"severity"`
	CVSS         float64 `json:"cvss"`
	ComponentRef string  `json:"componentRef"`
	Fix          string  `json:"fix"`
}

type htmlSummary struct {
	ComponentCount int `json:"componentCount"`
	FindingCount   int `json:"findingCount"`
	Critical       int `json:"critical"`
	High           int `json:"high"`
	Medium         int `json:"medium"`
	Low            int `json:"low"`
}

func (r *HTMLReporter) Write(w io.Writer, data any) error {
	tmpl, err := template.ParseFS(htmlTemplates, "templates/report.html.tmpl")
	if err != nil {
		return fmt.Errorf("parsing HTML template: %w", err)
	}

	// Convert data to JSON then back to our template struct for stable rendering.
	raw, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("marshaling data for HTML: %w", err)
	}

	var d htmlData
	if err := json.Unmarshal(raw, &d); err != nil {
		return fmt.Errorf("preparing HTML data: %w", err)
	}

	if err := tmpl.Execute(w, d); err != nil {
		return fmt.Errorf("rendering HTML report: %w", err)
	}

	return nil
}
