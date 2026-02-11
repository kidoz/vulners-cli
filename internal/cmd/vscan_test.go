package cmd

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kidoz/go-vulners/vscanner"
)

func vscanDeps(client *mockVScannerClient) *Deps {
	return &Deps{Intel: &mockIntelClient{}, VScanner: client}
}

func TestVScanProjectListCmd_JSONEnvelope(t *testing.T) {
	client := &mockVScannerClient{
		listProjectsFn: func(_ context.Context, _, _ int) ([]vscanner.Project, error) {
			return []vscanner.Project{{ID: "proj-1", Name: "test-project"}}, nil
		},
	}
	cmd := VScanProjectListCmd{}
	out := captureStdout(t, func() {
		err := cmd.Run(context.Background(), jsonCLI(), vscanDeps(client))
		require.NoError(t, err)
	})
	var envelope IntelOutput
	require.NoError(t, json.Unmarshal(out, &envelope))
	assert.Equal(t, "vscan project list", envelope.Command)
}

func TestVScanProjectCreateCmd_JSONEnvelope(t *testing.T) {
	client := &mockVScannerClient{
		createProjectFn: func(_ context.Context, req *vscanner.ProjectRequest) (*vscanner.Project, error) {
			return &vscanner.Project{ID: "proj-new", Name: req.Name}, nil
		},
	}
	cmd := VScanProjectCreateCmd{Name: "my-project", Description: "test"}
	out := captureStdout(t, func() {
		err := cmd.Run(context.Background(), jsonCLI(), vscanDeps(client))
		require.NoError(t, err)
	})
	var envelope IntelOutput
	require.NoError(t, json.Unmarshal(out, &envelope))
	assert.Equal(t, "vscan project create", envelope.Command)
}

func TestVScanTaskCreateCmd_JSONEnvelope(t *testing.T) {
	client := &mockVScannerClient{
		createTaskFn: func(_ context.Context, projectID string, req *vscanner.TaskRequest) (*vscanner.Task, error) {
			return &vscanner.Task{ID: "task-1", ProjectID: projectID, Name: req.Name}, nil
		},
	}
	cmd := VScanTaskCreateCmd{
		ProjectID: "proj-1",
		Name:      "scan-task",
		Targets:   []string{"192.168.1.0/24"},
		ScanType:  "fast",
	}
	out := captureStdout(t, func() {
		err := cmd.Run(context.Background(), jsonCLI(), vscanDeps(client))
		require.NoError(t, err)
	})
	var envelope IntelOutput
	require.NoError(t, json.Unmarshal(out, &envelope))
	assert.Equal(t, "vscan task create", envelope.Command)
}

func TestVScanTaskStartCmd_JSONEnvelope(t *testing.T) {
	client := &mockVScannerClient{}
	cmd := VScanTaskStartCmd{ProjectID: "proj-1", TaskID: "task-1"}
	out := captureStdout(t, func() {
		err := cmd.Run(context.Background(), jsonCLI(), vscanDeps(client))
		require.NoError(t, err)
	})
	var envelope IntelOutput
	require.NoError(t, json.Unmarshal(out, &envelope))
	assert.Equal(t, "vscan task start", envelope.Command)
}

func TestVScanResultStatsCmd_JSONEnvelope(t *testing.T) {
	client := &mockVScannerClient{
		getStatisticsFn: func(_ context.Context, _, _ string) (*vscanner.Statistics, error) {
			return &vscanner.Statistics{TotalHosts: 10, TotalVulns: 42}, nil
		},
	}
	cmd := VScanResultStatsCmd{ProjectID: "proj-1", ResultID: "res-1"}
	out := captureStdout(t, func() {
		err := cmd.Run(context.Background(), jsonCLI(), vscanDeps(client))
		require.NoError(t, err)
	})
	var envelope IntelOutput
	require.NoError(t, json.Unmarshal(out, &envelope))
	assert.Equal(t, "vscan result stats", envelope.Command)
}

func TestVScanLicenseCmd_JSONEnvelope(t *testing.T) {
	client := &mockVScannerClient{
		getLicensesFn: func(_ context.Context) ([]vscanner.License, error) {
			return []vscanner.License{{ID: "lic-1", Type: "enterprise", Hosts: 100}}, nil
		},
	}
	cmd := VScanLicenseCmd{}
	out := captureStdout(t, func() {
		err := cmd.Run(context.Background(), jsonCLI(), vscanDeps(client))
		require.NoError(t, err)
	})
	var envelope IntelOutput
	require.NoError(t, json.Unmarshal(out, &envelope))
	assert.Equal(t, "vscan license", envelope.Command)
}

func TestVScanCmd_NoAPIKey(t *testing.T) {
	cmd := VScanProjectListCmd{}
	err := cmd.Run(context.Background(), jsonCLI(), nilDeps())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "VULNERS_API_KEY")
}
