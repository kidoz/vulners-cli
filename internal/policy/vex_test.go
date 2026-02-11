package policy

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kidoz/vulners-cli/internal/model"
)

func TestLoadVEX(t *testing.T) {
	statuses, err := LoadVEX("../../testdata/sample.vex.json")
	require.NoError(t, err)

	assert.Equal(t, "not_affected", statuses["CVE-2021-44228"])
	assert.Equal(t, "fixed", statuses["CVE-2023-0001"])
	assert.Equal(t, "affected", statuses["CVE-2023-0002"])
}

func TestPolicy_FilterWithVEX(t *testing.T) {
	p := New("", nil)
	p.VEXStatuses = map[string]string{
		"CVE-2021-44228": "not_affected",
		"CVE-2023-0001":  "fixed",
		"CVE-2023-0002":  "affected",
	}

	findings := []model.Finding{
		{VulnID: "CVE-2021-44228", Severity: "critical"},
		{VulnID: "CVE-2023-0001", Severity: "high"},
		{VulnID: "CVE-2023-0002", Severity: "medium"},
		{VulnID: "CVE-2023-0003", Severity: "low"},
	}

	filtered := p.Filter(findings)
	assert.Len(t, filtered, 2)
	assert.Equal(t, "CVE-2023-0002", filtered[0].VulnID)
	assert.Equal(t, "CVE-2023-0003", filtered[1].VulnID)
}

func TestPolicy_VEX_PrimaryIDTakesPriority(t *testing.T) {
	p := New("", nil)
	p.VEXStatuses = map[string]string{
		"CVE-2024-0001": "affected",     // primary says affected
		"CVE-2024-9999": "not_affected", // alias says not_affected
	}

	findings := []model.Finding{
		{VulnID: "CVE-2024-0001", Severity: "high", Aliases: []string{"CVE-2024-9999"}},
	}

	filtered := p.Filter(findings)
	assert.Len(t, filtered, 1, "primary ID 'affected' should NOT be suppressed by alias 'not_affected'")
	assert.Equal(t, "CVE-2024-0001", filtered[0].VulnID)
}

func TestPolicy_VEX_AliasSuppressesWhenPrimaryUnknown(t *testing.T) {
	p := New("", nil)
	p.VEXStatuses = map[string]string{
		"GHSA-1234-5678": "fixed", // alias is fixed, primary has no VEX statement
	}

	findings := []model.Finding{
		{VulnID: "CVE-2024-0002", Severity: "high", Aliases: []string{"GHSA-1234-5678"}},
	}

	filtered := p.Filter(findings)
	assert.Len(t, filtered, 0, "alias 'fixed' should suppress when primary has no VEX statement")
}
