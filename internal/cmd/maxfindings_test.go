package cmd

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/kidoz/vulners-cli/internal/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMaxFindings_Truncates(t *testing.T) {
	findings := make([]model.Finding, 50)
	for i := range findings {
		findings[i] = model.Finding{
			VulnID:       fmt.Sprintf("CVE-2023-%04d", i),
			Severity:     "medium",
			ComponentRef: "pkg@1.0",
		}
	}
	components := []model.Component{{Name: "pkg", Version: "1.0"}}

	cli := &CLI{Output: "json", MaxFindings: 10}
	out := captureStdout(t, func() {
		err := writeOutput(cli, ".", components, findings, nil)
		require.NoError(t, err)
	})

	var result ScanOutput
	require.NoError(t, json.Unmarshal(out, &result))

	assert.Len(t, result.Findings, 10, "should truncate to 10 findings")
	assert.True(t, result.Truncated, "truncated should be true")
	assert.Equal(t, 50, result.TotalFindings, "totalFindings should reflect all 50")
	assert.Equal(t, 50, result.Summary.FindingCount, "summary should count all 50")
}

func TestMaxFindings_NoTruncation(t *testing.T) {
	findings := []model.Finding{
		{VulnID: "CVE-2023-0001", Severity: "high", ComponentRef: "pkg@1.0"},
		{VulnID: "CVE-2023-0002", Severity: "low", ComponentRef: "pkg@1.0"},
	}
	components := []model.Component{{Name: "pkg", Version: "1.0"}}

	cli := &CLI{Output: "json", MaxFindings: 10}
	out := captureStdout(t, func() {
		err := writeOutput(cli, ".", components, findings, nil)
		require.NoError(t, err)
	})

	var result ScanOutput
	require.NoError(t, json.Unmarshal(out, &result))

	assert.Len(t, result.Findings, 2, "should not truncate when under limit")
	assert.False(t, result.Truncated, "truncated should be false")
	assert.Zero(t, result.TotalFindings, "totalFindings should be omitted")
}

func TestMaxFindings_Zero_Unlimited(t *testing.T) {
	findings := make([]model.Finding, 25)
	for i := range findings {
		findings[i] = model.Finding{
			VulnID:       fmt.Sprintf("CVE-2023-%04d", i),
			Severity:     "low",
			ComponentRef: "pkg@1.0",
		}
	}
	components := []model.Component{{Name: "pkg", Version: "1.0"}}

	cli := &CLI{Output: "json", MaxFindings: 0}
	out := captureStdout(t, func() {
		err := writeOutput(cli, ".", components, findings, nil)
		require.NoError(t, err)
	})

	var result ScanOutput
	require.NoError(t, json.Unmarshal(out, &result))

	assert.Len(t, result.Findings, 25, "zero means unlimited")
	assert.False(t, result.Truncated)
}
