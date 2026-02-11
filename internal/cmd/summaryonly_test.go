package cmd

import (
	"encoding/json"
	"testing"

	"github.com/kidoz/vulners-cli/internal/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSummaryOnly_EmptyListsWithTopFindings(t *testing.T) {
	findings := []model.Finding{
		{VulnID: "CVE-2023-0001", Severity: "critical", CVSS: 9.8, ComponentRef: "a@1.0"},
		{VulnID: "CVE-2023-0002", Severity: "high", CVSS: 7.5, ComponentRef: "a@1.0"},
		{VulnID: "CVE-2023-0003", Severity: "medium", CVSS: 5.0, ComponentRef: "b@2.0"},
		{VulnID: "CVE-2023-0004", Severity: "low", CVSS: 2.0, ComponentRef: "b@2.0"},
		{VulnID: "CVE-2023-0005", Severity: "high", CVSS: 8.0, ComponentRef: "c@3.0"},
		{VulnID: "CVE-2023-0006", Severity: "medium", CVSS: 4.0, ComponentRef: "c@3.0"},
	}
	components := []model.Component{
		{Name: "a", Version: "1.0"},
		{Name: "b", Version: "2.0"},
		{Name: "c", Version: "3.0"},
	}

	cli := &CLI{Output: "json", SummaryOnly: true}
	out := captureStdout(t, func() {
		err := writeOutput(cli, ".", components, findings, nil)
		require.NoError(t, err)
	})

	var result ScanOutput
	require.NoError(t, json.Unmarshal(out, &result))

	// Components and findings should be empty.
	assert.Empty(t, result.Components, "components should be empty")
	assert.Empty(t, result.Findings, "findings should be empty")

	// Summary should reflect all findings.
	assert.Equal(t, 6, result.Summary.FindingCount)
	assert.Equal(t, 3, result.Summary.ComponentCount)
	assert.Equal(t, 1, result.Summary.Critical)
	assert.Equal(t, 2, result.Summary.High)
	assert.Equal(t, 2, result.Summary.Medium)
	assert.Equal(t, 1, result.Summary.Low)

	// TopFindings should have top 5 sorted by severity.
	require.Len(t, result.TopFindings, 5)
	assert.Equal(t, "critical", result.TopFindings[0].Severity)
	assert.Equal(t, "CVE-2023-0001", result.TopFindings[0].VulnID)
}

func TestSummaryOnly_FewerThan5(t *testing.T) {
	findings := []model.Finding{
		{VulnID: "CVE-2023-0001", Severity: "high", ComponentRef: "a@1.0"},
		{VulnID: "CVE-2023-0002", Severity: "low", ComponentRef: "a@1.0"},
	}
	components := []model.Component{{Name: "a", Version: "1.0"}}

	cli := &CLI{Output: "json", SummaryOnly: true}
	out := captureStdout(t, func() {
		err := writeOutput(cli, ".", components, findings, nil)
		require.NoError(t, err)
	})

	var result ScanOutput
	require.NoError(t, json.Unmarshal(out, &result))

	assert.Empty(t, result.Findings)
	require.Len(t, result.TopFindings, 2, "should return all findings when fewer than 5")
	assert.Equal(t, 2, result.Summary.FindingCount)
}

func TestSummaryOnly_NoFindings(t *testing.T) {
	components := []model.Component{{Name: "a", Version: "1.0"}}

	cli := &CLI{Output: "json", SummaryOnly: true}
	out := captureStdout(t, func() {
		err := writeOutput(cli, ".", components, nil, nil)
		require.NoError(t, err)
	})

	var result ScanOutput
	require.NoError(t, json.Unmarshal(out, &result))

	assert.Empty(t, result.Findings)
	assert.Empty(t, result.TopFindings)
	assert.Equal(t, 0, result.Summary.FindingCount)
}
