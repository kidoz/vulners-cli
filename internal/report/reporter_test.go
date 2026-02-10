package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/kidoz/vulners-cli/internal/model"
)

func TestNew_ReturnsCorrectType(t *testing.T) {
	tests := []struct {
		format model.OutputFormat
	}{
		{model.OutputJSON},
		{model.OutputTable},
		{model.OutputSARIF},
		{model.OutputHTML},
		{model.OutputCycloneDX},
		{"unknown"},
	}
	for _, tt := range tests {
		r := New(tt.format)
		if r == nil {
			t.Errorf("New(%q) returned nil", tt.format)
		}
	}
}

func TestJSONReporter_Write(t *testing.T) {
	r := &JSONReporter{}
	var buf bytes.Buffer

	data := map[string]string{"key": "value"}
	if err := r.Write(&buf, data); err != nil {
		t.Fatalf("JSONReporter.Write() error: %v", err)
	}

	var got map[string]string
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("invalid JSON output: %v", err)
	}
	if got["key"] != "value" {
		t.Errorf("got key=%q, want %q", got["key"], "value")
	}
}

func TestTableReporter_WriteSlice(t *testing.T) {
	r := &TableReporter{}
	var buf bytes.Buffer

	data := []map[string]string{
		{"name": "foo", "version": "1.0"},
		{"name": "bar", "version": "2.0"},
	}
	if err := r.Write(&buf, data); err != nil {
		t.Fatalf("TableReporter.Write() error: %v", err)
	}

	out := buf.String()
	if !strings.Contains(out, "foo") || !strings.Contains(out, "bar") {
		t.Errorf("table output missing data: %s", out)
	}
	if !strings.Contains(out, "name") {
		t.Errorf("table output missing header: %s", out)
	}
}

func TestTableReporter_WriteMap(t *testing.T) {
	r := &TableReporter{}
	var buf bytes.Buffer

	data := map[string]string{"status": "ok"}
	if err := r.Write(&buf, data); err != nil {
		t.Fatalf("TableReporter.Write() error: %v", err)
	}
	if !strings.Contains(buf.String(), "status") {
		t.Errorf("table output missing key: %s", buf.String())
	}
}

func TestTableReporter_WriteEmpty(t *testing.T) {
	r := &TableReporter{}
	var buf bytes.Buffer

	if err := r.Write(&buf, []any{}); err != nil {
		t.Fatalf("TableReporter.Write() error: %v", err)
	}
	if !strings.Contains(buf.String(), "no results") {
		t.Errorf("expected 'no results', got: %s", buf.String())
	}
}

func TestSARIFReporter_Write(t *testing.T) {
	r := &SARIFReporter{}
	var buf bytes.Buffer

	data := struct {
		Target   string `json:"target"`
		Findings []struct {
			VulnID       string `json:"vulnID"`
			Severity     string `json:"severity"`
			ComponentRef string `json:"componentRef"`
		} `json:"findings"`
	}{
		Target: "test-repo",
		Findings: []struct {
			VulnID       string `json:"vulnID"`
			Severity     string `json:"severity"`
			ComponentRef string `json:"componentRef"`
		}{
			{VulnID: "CVE-2021-44228", Severity: "critical", ComponentRef: "log4j@2.14.0"},
			{VulnID: "CVE-2023-1234", Severity: "medium", ComponentRef: "foo@1.0"},
		},
	}

	if err := r.Write(&buf, data); err != nil {
		t.Fatalf("SARIFReporter.Write() error: %v", err)
	}

	var sarif sarifLog
	if err := json.Unmarshal(buf.Bytes(), &sarif); err != nil {
		t.Fatalf("invalid SARIF output: %v", err)
	}
	if sarif.Version != "2.1.0" {
		t.Errorf("SARIF version = %q, want 2.1.0", sarif.Version)
	}
	if len(sarif.Runs) != 1 {
		t.Fatalf("expected 1 run, got %d", len(sarif.Runs))
	}
	run := sarif.Runs[0]

	// Verify rules array.
	if len(run.Tool.Driver.Rules) != 2 {
		t.Errorf("expected 2 rules, got %d", len(run.Tool.Driver.Rules))
	}
	if run.Tool.Driver.InformationURI == "" {
		t.Error("missing informationUri on SARIF driver")
	}

	// Verify results.
	if len(run.Results) != 2 {
		t.Fatalf("expected 2 results, got %d", len(run.Results))
	}
	if run.Results[0].Level != "error" {
		t.Errorf("critical severity should map to 'error', got %q", run.Results[0].Level)
	}
	if run.Results[1].Level != "warning" {
		t.Errorf("medium severity should map to 'warning', got %q", run.Results[1].Level)
	}

	// Verify locations present (required by GitHub Code Scanning).
	if len(run.Results[0].Locations) == 0 {
		t.Error("SARIF result missing locations array")
	}

	// Verify artifact URI uses target path, not componentRef (SARIF spec compliance).
	for i, r := range run.Results {
		uri := r.Locations[0].PhysicalLocation.ArtifactLocation.URI
		if uri != "test-repo" {
			t.Errorf("result[%d] location URI = %q, want %q", i, uri, "test-repo")
		}
	}
}

func TestHTMLReporter_Write(t *testing.T) {
	r := &HTMLReporter{}
	var buf bytes.Buffer

	data := htmlData{
		SchemaVersion: "1.0.0",
		Target:        "test-target",
		Findings: []htmlFinding{
			{VulnID: "CVE-2021-1234", Severity: "high", CVSS: 7.5, ComponentRef: "pkg@1.0"},
		},
		Summary: htmlSummary{
			ComponentCount: 1,
			FindingCount:   1,
			High:           1,
		},
	}

	if err := r.Write(&buf, data); err != nil {
		t.Fatalf("HTMLReporter.Write() error: %v", err)
	}

	out := buf.String()
	if !strings.Contains(out, "<!DOCTYPE html>") {
		t.Error("HTML output missing DOCTYPE")
	}
	if !strings.Contains(out, "CVE-2021-1234") {
		t.Error("HTML output missing vulnerability ID")
	}
	if !strings.Contains(out, "test-target") {
		t.Error("HTML output missing target")
	}
}

func TestHTMLReporter_WriteNoFindings(t *testing.T) {
	r := &HTMLReporter{}
	var buf bytes.Buffer

	data := htmlData{Target: "empty-scan"}
	if err := r.Write(&buf, data); err != nil {
		t.Fatalf("HTMLReporter.Write() error: %v", err)
	}
	if !strings.Contains(buf.String(), "No findings") {
		t.Error("expected 'No findings' for empty scan")
	}
}

func TestTruncate(t *testing.T) {
	tests := []struct {
		input string
		max   int
		want  string
	}{
		{"hello", 10, "hello"},
		{"hello world", 5, "he..."},
		{"hello world", 8, "hello..."},
		{"hello world", 3, "hel"},
		{"hello world", 2, "he"},
		{"hello world", 1, "h"},
		{"hello world", 0, ""},
		{"", 5, ""},
	}
	for _, tt := range tests {
		got := truncate(tt.input, tt.max)
		if got != tt.want {
			t.Errorf("truncate(%q, %d) = %q, want %q", tt.input, tt.max, got, tt.want)
		}
	}
}

func TestSarifLevel(t *testing.T) {
	tests := []struct {
		severity string
		want     string
	}{
		{"critical", "error"},
		{"high", "error"},
		{"medium", "warning"},
		{"low", "note"},
		{"unknown", "note"},
	}
	for _, tt := range tests {
		if got := sarifLevel(tt.severity); got != tt.want {
			t.Errorf("sarifLevel(%q) = %q, want %q", tt.severity, got, tt.want)
		}
	}
}
