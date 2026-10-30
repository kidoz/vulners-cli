//go:build integration

package cmd

import (
	"context"
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/kidoz/vulners-cli/internal/intel"
	"github.com/kidoz/vulners-cli/internal/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func liveScanDeps(t *testing.T) *Deps {
	t.Helper()
	key := os.Getenv("VULNERS_API_KEY")
	if key == "" {
		t.Skip("set VULNERS_API_KEY to run live API integration tests")
	}
	client, err := intel.NewVulnersClient(key, discardLogger())
	require.NoError(t, err)
	return &Deps{Intel: client}
}

func TestIntegration_SBOMAudit(t *testing.T) {
	deps := liveScanDeps(t)
	for _, format := range []string{"cyclonedx", "spdx"} {
		t.Run(format, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
			defer cancel()
			command := &ScanSBOMCmd{File: "../../testdata/" + format + ".json", Format: format}
			var runErr error
			output := captureStdout(t, func() {
				runErr = command.Run(ctx, jsonCLI(), deps, nil, discardLogger())
			})
			require.NoError(t, runErr)
			var result ScanOutput
			require.NoError(t, json.Unmarshal(output, &result))
			assert.NotEmpty(t, result.Components)
		})
	}
}

func TestIntegration_WebScanPolicy(t *testing.T) {
	deps := liveScanDeps(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	cli := jsonCLI()
	cli.FailOn = "low"
	var runErr error
	output := captureStdout(t, func() {
		runErr = (&ScanWebCmd{Path: []string{"/wp-login.php"}}).Run(ctx, cli, deps)
	})
	var exitErr *model.ExitError
	require.ErrorAs(t, runErr, &exitErr)
	assert.Equal(t, model.ExitFindings, exitErr.Code)
	var result ScanOutput
	require.NoError(t, json.Unmarshal(output, &result))
	var scored bool
	for _, finding := range result.Findings {
		scored = scored || finding.CVSS > 0
	}
	assert.True(t, scored, "expected at least one scored finding for a known web path")
}
