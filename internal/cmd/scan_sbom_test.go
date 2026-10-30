package cmd

import (
	"encoding/json"
	"os"
	"testing"

	vulners "github.com/kidoz/go-vulners"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestConvertSBOMFindings_NestedMetrics(t *testing.T) {
	raw, err := os.ReadFile("../../testdata/api/sbom_audit.json")
	require.NoError(t, err)
	var response struct {
		Result vulners.SBOMAuditResult `json:"result"`
	}
	require.NoError(t, json.Unmarshal(raw, &response))
	findings := convertSBOMFindings(response.Result.Packages)
	require.Len(t, findings, 1)
	assert.Equal(t, "critical", findings[0].Severity)
	assert.Equal(t, 9.8, findings[0].CVSS)
	require.NotNil(t, findings[0].EPSS)
	assert.Equal(t, 0.42, *findings[0].EPSS)
	assert.Equal(t, "4.17.21", findings[0].Fix)
}

func TestSBOMEPSSTopLevelFallback(t *testing.T) {
	advisory := vulners.SBOMAdvisory{
		EPSS:    []vulners.Epss{{Epss: 0.2}},
		Metrics: &vulners.SBOMMetrics{EPSS: []vulners.Epss{{Cve: "CVE-TEST"}}},
	}
	require.NotNil(t, sbomEPSS(advisory))
	assert.Equal(t, 0.2, *sbomEPSS(advisory))
	assert.Nil(t, sbomEPSS(vulners.SBOMAdvisory{}))
}
