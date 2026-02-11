package cmd

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	vulners "github.com/kidoz/go-vulners"
)

func TestReportSummaryCmd_JSONEnvelope(t *testing.T) {
	client := &mockIntelClient{
		vulnsSummaryReportFn: func(_ context.Context, _, _ int) (*vulners.VulnsSummary, error) {
			return &vulners.VulnsSummary{Total: 42, Critical: 5, High: 10}, nil
		},
	}

	cmd := ReportSummaryCmd{Limit: 100, Offset: 0}
	out := captureStdout(t, func() {
		err := cmd.Run(context.Background(), jsonCLI(), testDeps(client))
		require.NoError(t, err)
	})

	var envelope IntelOutput
	require.NoError(t, json.Unmarshal(out, &envelope))
	assert.Equal(t, "report summary", envelope.Command)
}

func TestReportVulnsCmd_JSONEnvelope(t *testing.T) {
	client := &mockIntelClient{
		vulnsListFn: func(_ context.Context, _, _ int) ([]vulners.VulnItem, error) {
			return []vulners.VulnItem{{ID: "CVE-2021-44228", Severity: "critical"}}, nil
		},
	}

	cmd := ReportVulnsCmd{Limit: 10}
	out := captureStdout(t, func() {
		err := cmd.Run(context.Background(), jsonCLI(), testDeps(client))
		require.NoError(t, err)
	})

	var envelope IntelOutput
	require.NoError(t, json.Unmarshal(out, &envelope))
	assert.Equal(t, "report vulns", envelope.Command)
}

func TestReportHostsCmd_JSONEnvelope(t *testing.T) {
	client := &mockIntelClient{
		hostVulnsFn: func(_ context.Context, _, _ int) ([]vulners.HostVuln, error) {
			return []vulners.HostVuln{{ID: "1", Host: "192.168.1.1"}}, nil
		},
	}

	cmd := ReportHostsCmd{Limit: 10}
	out := captureStdout(t, func() {
		err := cmd.Run(context.Background(), jsonCLI(), testDeps(client))
		require.NoError(t, err)
	})

	var envelope IntelOutput
	require.NoError(t, json.Unmarshal(out, &envelope))
	assert.Equal(t, "report hosts", envelope.Command)
}

func TestReportScansCmd_JSONEnvelope(t *testing.T) {
	client := &mockIntelClient{
		scanListFn: func(_ context.Context, _, _ int) ([]vulners.ScanItem, error) {
			return []vulners.ScanItem{{ID: "scan-1", Name: "daily"}}, nil
		},
	}

	cmd := ReportScansCmd{Limit: 10}
	out := captureStdout(t, func() {
		err := cmd.Run(context.Background(), jsonCLI(), testDeps(client))
		require.NoError(t, err)
	})

	var envelope IntelOutput
	require.NoError(t, json.Unmarshal(out, &envelope))
	assert.Equal(t, "report scans", envelope.Command)
}

func TestReportIPsCmd_JSONEnvelope(t *testing.T) {
	client := &mockIntelClient{
		ipSummaryReportFn: func(_ context.Context) (*vulners.IPSummary, error) {
			return &vulners.IPSummary{Total: 100, WithVulns: 30}, nil
		},
	}

	cmd := ReportIPsCmd{}
	out := captureStdout(t, func() {
		err := cmd.Run(context.Background(), jsonCLI(), testDeps(client))
		require.NoError(t, err)
	})

	var envelope IntelOutput
	require.NoError(t, json.Unmarshal(out, &envelope))
	assert.Equal(t, "report ips", envelope.Command)
}

func TestReportCmd_OfflineError(t *testing.T) {
	cli := jsonCLI()
	cli.Offline = true

	cmd := ReportSummaryCmd{Limit: 10}
	err := cmd.Run(context.Background(), cli, testDeps(&mockIntelClient{}))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "offline")
}

func TestReportCmd_NoAPIKey(t *testing.T) {
	cmd := ReportSummaryCmd{Limit: 10}
	err := cmd.Run(context.Background(), jsonCLI(), nilDeps())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "VULNERS_API_KEY")
}
