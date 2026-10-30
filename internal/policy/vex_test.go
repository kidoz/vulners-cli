package policy

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kidoz/vulners-cli/internal/model"
)

func TestLoadVEX(t *testing.T) {
	statements, err := LoadVEX("../../testdata/sample.vex.json")
	require.NoError(t, err)
	require.Len(t, statements["CVE-2021-44228"], 1)
	assert.Equal(t, "not_affected", statements["CVE-2021-44228"][0].Status)
	assert.Equal(t, []string{"pkg:npm/lodash@4.17.20"}, statements["CVE-2021-44228"][0].Products)
	assert.Equal(t, "fixed", statements["CVE-2023-0001"][0].Status)
	assert.Equal(t, "affected", statements["CVE-2023-0002"][0].Status)
}

func TestLoadVEXRejectsMissingProducts(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vex.json")
	err := os.WriteFile(path, []byte(`{"statements":[{"vulnerability":{"name":"CVE-2024-0001"},"status":"fixed"}]}`), 0o600)
	require.NoError(t, err)
	_, err = LoadVEX(path)
	require.ErrorContains(t, err, "has no products")
}

func TestPolicy_FilterWithVEX(t *testing.T) {
	p := New("", nil)
	p.VEXStatements = map[string][]VEXStatement{
		"CVE-2021-44228": {{Status: "not_affected", Products: []string{"pkg:npm/lodash@4.17.20"}}},
		"CVE-2023-0001":  {{Status: "fixed", Products: []string{"pkg:npm/lodash@4.17.20"}}},
		"CVE-2023-0002":  {{Status: "affected", Products: []string{"pkg:npm/lodash@4.17.20"}}},
	}
	components := []model.Component{{Name: "lodash", Version: "4.17.20", PURL: "pkg:npm/lodash@4.17.20"}}
	findings := []model.Finding{
		{VulnID: "CVE-2021-44228", Severity: "critical", ComponentRef: "lodash@4.17.20"},
		{VulnID: "CVE-2023-0001", Severity: "high", ComponentRef: "lodash@4.17.20"},
		{VulnID: "CVE-2023-0002", Severity: "medium", ComponentRef: "lodash@4.17.20"},
		{VulnID: "CVE-2023-0003", Severity: "low", ComponentRef: "lodash@4.17.20"},
	}

	filtered := p.Filter(findings, components)
	require.Len(t, filtered, 2)
	assert.Equal(t, "CVE-2023-0002", filtered[0].VulnID)
	assert.Equal(t, "CVE-2023-0003", filtered[1].VulnID)
}

func TestPolicy_VEXDoesNotSuppressDifferentProduct(t *testing.T) {
	p := New("", nil)
	p.VEXStatements = map[string][]VEXStatement{
		"CVE-2024-0001": {{Status: "not_affected", Products: []string{"pkg:npm/other@1.0"}}},
	}
	components := []model.Component{{Name: "lodash", Version: "4.17.20", PURL: "pkg:npm/lodash@4.17.20"}}
	findings := []model.Finding{{VulnID: "CVE-2024-0001", ComponentRef: "lodash@4.17.20"}}
	assert.Len(t, p.Filter(findings, components), 1)
}

func TestPolicy_VEXPrimaryIDTakesPriority(t *testing.T) {
	p := New("", nil)
	p.VEXStatements = map[string][]VEXStatement{
		"CVE-2024-0001": {{Status: "affected", Products: []string{"pkg@1.0"}}},
		"CVE-2024-9999": {{Status: "not_affected", Products: []string{"pkg@1.0"}}},
	}
	findings := []model.Finding{{VulnID: "CVE-2024-0001", Aliases: []string{"CVE-2024-9999"}, ComponentRef: "pkg@1.0"}}
	assert.Len(t, p.Filter(findings, nil), 1)
}

func TestPolicy_VEXAliasSuppressesWhenPrimaryUnknown(t *testing.T) {
	p := New("", nil)
	p.VEXStatements = map[string][]VEXStatement{
		"GHSA-1234-5678": {{Status: "fixed", Products: []string{"pkg@1.0"}}},
	}
	findings := []model.Finding{{VulnID: "CVE-2024-0002", Aliases: []string{"GHSA-1234-5678"}, ComponentRef: "pkg@1.0"}}
	assert.Empty(t, p.Filter(findings, nil))
}
