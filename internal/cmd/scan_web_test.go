package cmd

import (
	"context"
	"fmt"
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
	assert.Contains(t, string(out), "scan web")
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
