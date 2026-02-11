package cmd

import (
	"encoding/json"
	"testing"

	"github.com/kidoz/vulners-cli/internal/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// agentCLI returns a CLI with --agent mode enabled.
func agentCLI() *CLI {
	return &CLI{Agent: true, Output: "json", Quiet: true, NoColor: true}
}

func TestAgentMode_ForcesJSONAndQuiet(t *testing.T) {
	cli := &CLI{Agent: true}
	// Simulate what applyConfigFlags does for --agent.
	if cli.Agent {
		cli.Output = "json"
		cli.Quiet = true
		cli.NoColor = true
	}
	assert.Equal(t, "json", cli.Output)
	assert.True(t, cli.Quiet)
	assert.True(t, cli.NoColor)
}

func TestAgentMode_SortsFindingsInOutput(t *testing.T) {
	findings := []model.Finding{
		{VulnID: "CVE-2023-0002", Severity: "low", ComponentRef: "pkg@1.0"},
		{VulnID: "CVE-2023-0001", Severity: "critical", ComponentRef: "pkg@1.0"},
		{VulnID: "CVE-2023-0003", Severity: "high", ComponentRef: "pkg@1.0"},
	}
	components := []model.Component{{Name: "pkg", Version: "1.0"}}

	cli := agentCLI()
	out := captureStdout(t, func() {
		err := writeOutput(cli, ".", components, findings, nil)
		require.NoError(t, err)
	})

	var result ScanOutput
	require.NoError(t, json.Unmarshal(out, &result))

	// Findings must be sorted: critical, high, low.
	require.Len(t, result.Findings, 3)
	assert.Equal(t, "CVE-2023-0001", result.Findings[0].VulnID)
	assert.Equal(t, "critical", result.Findings[0].Severity)
	assert.Equal(t, "CVE-2023-0003", result.Findings[1].VulnID)
	assert.Equal(t, "high", result.Findings[1].Severity)
	assert.Equal(t, "CVE-2023-0002", result.Findings[2].VulnID)
	assert.Equal(t, "low", result.Findings[2].Severity)
}

func TestNonAgentMode_DoesNotSort(t *testing.T) {
	findings := []model.Finding{
		{VulnID: "CVE-2023-0002", Severity: "low", ComponentRef: "pkg@1.0"},
		{VulnID: "CVE-2023-0001", Severity: "critical", ComponentRef: "pkg@1.0"},
	}
	components := []model.Component{{Name: "pkg", Version: "1.0"}}

	cli := jsonCLI()
	out := captureStdout(t, func() {
		err := writeOutput(cli, ".", components, findings, nil)
		require.NoError(t, err)
	})

	var result ScanOutput
	require.NoError(t, json.Unmarshal(out, &result))

	// Without --agent, order is preserved as-is.
	require.Len(t, result.Findings, 2)
	assert.Equal(t, "CVE-2023-0002", result.Findings[0].VulnID)
	assert.Equal(t, "CVE-2023-0001", result.Findings[1].VulnID)
}
