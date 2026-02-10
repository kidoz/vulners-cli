package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func cdxTestBOM(t *testing.T) map[string]any {
	t.Helper()
	r := &CycloneDXReporter{}
	var buf bytes.Buffer

	data := map[string]any{
		"target": "test-repo",
		"components": []map[string]string{
			{"name": "log4j", "version": "2.14.0", "type": "library", "purl": "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.0"},
		},
		"findings": []map[string]any{
			{"vulnID": "CVE-2021-44228", "severity": "critical", "cvss": 10.0, "componentRef": "log4j@2.14.0"},
		},
	}

	if err := r.Write(&buf, data); err != nil {
		t.Fatalf("CycloneDXReporter.Write() error: %v", err)
	}

	var bom map[string]any
	if err := json.Unmarshal(buf.Bytes(), &bom); err != nil {
		t.Fatalf("invalid CycloneDX JSON: %v", err)
	}
	return bom
}

func TestCycloneDXReporter_Write(t *testing.T) {
	bom := cdxTestBOM(t)

	if specVer, ok := bom["specVersion"].(string); !ok || specVer == "" {
		t.Error("missing specVersion in CycloneDX output")
	}
	if comps, ok := bom["components"].([]any); !ok || len(comps) != 1 {
		t.Errorf("expected 1 component, got %v", bom["components"])
	}
	if vulns, ok := bom["vulnerabilities"].([]any); !ok || len(vulns) != 1 {
		t.Errorf("expected 1 vulnerability, got %v", bom["vulnerabilities"])
	}
}

func TestCycloneDXReporter_SerialNumber(t *testing.T) {
	bom := cdxTestBOM(t)
	serial, _ := bom["serialNumber"].(string)
	if !strings.HasPrefix(serial, "urn:uuid:") {
		t.Errorf("serialNumber should start with urn:uuid:, got %q", serial)
	}
	uuidPart := strings.TrimPrefix(serial, "urn:uuid:")
	if len(uuidPart) != 36 {
		t.Errorf("UUID should be 36 chars, got %d: %q", len(uuidPart), uuidPart)
	}
}

func TestCycloneDXReporter_BomRef(t *testing.T) {
	bom := cdxTestBOM(t)

	comps := bom["components"].([]any)
	comp := comps[0].(map[string]any)
	if _, ok := comp["bom-ref"]; !ok {
		t.Error("component missing bom-ref")
	}

	vulnList := bom["vulnerabilities"].([]any)
	vuln := vulnList[0].(map[string]any)
	affects := vuln["affects"].([]any)
	affect := affects[0].(map[string]any)
	ref := affect["ref"].(string)
	if ref == "log4j@2.14.0" {
		t.Error("affects.ref should use bom-ref, not raw componentRef")
	}
	if !strings.HasPrefix(ref, "comp-") {
		t.Errorf("affects.ref should be a bom-ref (comp-N), got %q", ref)
	}
}

func TestCycloneDXReporter_WriteEmpty(t *testing.T) {
	r := &CycloneDXReporter{}
	var buf bytes.Buffer

	data := map[string]any{
		"target":     "empty",
		"components": []map[string]string{},
		"findings":   []map[string]any{},
	}

	if err := r.Write(&buf, data); err != nil {
		t.Fatalf("CycloneDXReporter.Write() error: %v", err)
	}

	var bom map[string]any
	if err := json.Unmarshal(buf.Bytes(), &bom); err != nil {
		t.Fatalf("invalid CycloneDX JSON: %v", err)
	}
}

func TestCdxComponentType(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"library", "library"},
		{"go-module", "library"},
		{"go", "library"},
		{"npm", "library"},
		{"pip", "library"},
		{"framework", "framework"},
		{"application", "application"},
		{"firmware", "firmware"},
		{"operating-system", "operating-system"},
		{"unknown-type", "library"},
		{"", "library"},
	}
	for _, tt := range tests {
		got := string(cdxComponentType(tt.input))
		if got != tt.want {
			t.Errorf("cdxComponentType(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestGenerateUUID(t *testing.T) {
	uuid := generateUUID()
	if len(uuid) != 36 {
		t.Errorf("UUID length = %d, want 36", len(uuid))
	}
	// Version should be 4.
	if uuid[14] != '4' {
		t.Errorf("UUID version byte = %c, want '4'", uuid[14])
	}
	// Each call should produce a different value.
	uuid2 := generateUUID()
	if uuid == uuid2 {
		t.Error("generateUUID() returned same value twice")
	}
}

func TestCdxSeverity(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"critical", "critical"},
		{"high", "high"},
		{"medium", "medium"},
		{"low", "low"},
		{"unknown", "unknown"},
		{"", "unknown"},
	}
	for _, tt := range tests {
		got := string(cdxSeverity(tt.input))
		if got != tt.want {
			t.Errorf("cdxSeverity(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}
