package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"testing"

	vulners "github.com/kidoz/go-vulners"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestScanWebCmd_Happy(t *testing.T) {
	client := &mockIntelClient{
		getWebVulnsFn: func(_ context.Context, paths []string, application any) (map[string][]vulners.WebVulnerability, error) {
			assert.Equal(t, []string{"/wp-login.php"}, paths)
			assert.Nil(t, application)
			return map[string][]vulners.WebVulnerability{
				"/wp-login.php": {{ID: "CVE-2024-0001", Type: "cve"}},
			}, nil
		},
	}

	cmd := ScanWebCmd{Path: []string{"/wp-login.php"}}
	out := captureStdout(t, func() {
		err := cmd.Run(context.Background(), jsonCLI(), testDeps(client))
		require.NoError(t, err)
	})
	assert.Contains(t, string(out), `"findings"`)
	assert.Contains(t, string(out), "CVE-2024-0001")
}

func TestScanWebCmd_WithApplication(t *testing.T) {
	client := &mockIntelClient{
		getWebVulnsFn: func(_ context.Context, paths []string, application any) (map[string][]vulners.WebVulnerability, error) {
			app, ok := application.(map[string]string)
			require.True(t, ok, "application should be a map")
			assert.Equal(t, "wordpress", app["product"])
			assert.Equal(t, "6.4", app["version"])
			return nil, nil
		},
	}

	cmd := ScanWebCmd{Path: []string{"/"}, Software: "wordpress", SoftwareVersion: "6.4"}
	captureStdout(t, func() {
		err := cmd.Run(context.Background(), jsonCLI(), testDeps(client))
		require.NoError(t, err)
	})
}

func TestScanWebCmd_NilIntel(t *testing.T) {
	cmd := ScanWebCmd{Path: []string{"/"}}
	err := cmd.Run(context.Background(), jsonCLI(), nilDeps())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "VULNERS_API_KEY")
}

func TestScanWebCmd_Offline(t *testing.T) {
	cmd := ScanWebCmd{Path: []string{"/"}}
	err := cmd.Run(context.Background(), offlineCLI(), testDeps(&mockIntelClient{}))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "offline")
}

func TestScanWebCmd_APIError(t *testing.T) {
	client := &mockIntelClient{
		getWebVulnsFn: func(context.Context, []string, any) (map[string][]vulners.WebVulnerability, error) {
			return nil, fmt.Errorf("boom")
		},
	}

	cmd := ScanWebCmd{Path: []string{"/"}}
	err := cmd.Run(context.Background(), jsonCLI(), testDeps(client))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "web scanning failed")
}

func webFixture(t *testing.T) map[string][]vulners.WebVulnerability {
	t.Helper()
	raw, err := os.ReadFile("../../testdata/api/web_vulnerabilities.json")
	require.NoError(t, err)
	var result map[string][]vulners.WebVulnerability
	require.NoError(t, json.Unmarshal(raw, &result))
	return result
}

func TestWebSeverity(t *testing.T) {
	for _, tc := range []struct {
		name, metrics string
		score         float64
		severity      string
	}{
		{"legacy number", `{"cvss":7.5}`, 7.5, "high"},
		{"legacy object", `{"cvss3":{"score":9.8}}`, 9.8, "critical"},
		{"providers", `{"nvd":{"cvss31":{"baseScore":7.5}},"nva":{"cvss31":{"baseScore":9.8}}}`, 9.8, "critical"},
		{"version priority", `{"cvss3":9.8,"nvd":{"cvss40":{"baseScore":4.3}}}`, 4.3, "medium"},
		{"invalid fallback", `{"nvd":{"cvss4":{"baseScore":11},"cvss31":{"baseScore":2.1}}}`, 2.1, "low"},
		{"unrelated score", `{"epss":{"score":0.9},"ai":{"score":9.8}}`, 0, "unknown"},
		{"invalid", `{"cvss":-1,"nvd":{"cvss31":"bad"}}`, 0, "unknown"},
		{"null", `{"cvss":null}`, 0, "unknown"},
		{"empty", `{}`, 0, "unknown"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var metrics map[string]any
			require.NoError(t, json.Unmarshal([]byte(tc.metrics), &metrics))
			for range 20 {
				score, severity := webSeverity(metrics)
				assert.Equal(t, tc.score, score)
				assert.Equal(t, tc.severity, severity)
			}
		})
	}
}
