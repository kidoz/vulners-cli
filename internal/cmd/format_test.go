package cmd

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/kidoz/vulners-cli/internal/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestValidateNonScanFormat(t *testing.T) {
	tests := []struct {
		name    string
		format  string
		wantErr bool
	}{
		{name: "json allowed", format: "json", wantErr: false},
		{name: "table allowed", format: "table", wantErr: false},
		{name: "sarif rejected", format: "sarif", wantErr: true},
		{name: "html rejected", format: "html", wantErr: true},
		{name: "cyclonedx rejected", format: "cyclonedx", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateNonScanFormat(tt.format)
			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), "only supported for scan commands")
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestOutputWriter_Stdout(t *testing.T) {
	cli := jsonCLI()
	w, closer, err := outputWriter(cli)
	require.NoError(t, err)
	defer func() { _ = closer() }()
	assert.Equal(t, os.Stdout, w)
}

func TestOutputWriter_File(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "report.json")

	cli := &CLI{Output: "json", OutputFile: path}

	// Use writeOutput to exercise the full path.
	findings := []model.Finding{
		{VulnID: "CVE-2023-0001", Severity: "high", ComponentRef: "pkg@1.0"},
	}
	components := []model.Component{{Name: "pkg", Version: "1.0"}}

	// Stdout should be empty.
	out := captureStdout(t, func() {
		err := writeOutput(cli, ".", components, findings, nil)
		require.NoError(t, err)
	})
	assert.Empty(t, out, "stdout should be empty when --output-file is set")

	// File should contain valid JSON.
	data, err := os.ReadFile(path)
	require.NoError(t, err)

	var result ScanOutput
	require.NoError(t, json.Unmarshal(data, &result))
	assert.Equal(t, "CVE-2023-0001", result.Findings[0].VulnID)
	assert.Equal(t, 1, result.Summary.FindingCount)
}

func TestOutputWriter_BadPath(t *testing.T) {
	cli := &CLI{Output: "json", OutputFile: "/nonexistent/dir/file.json"}
	_, _, err := outputWriter(cli)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "opening output file")
}
