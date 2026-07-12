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
			assert.Equal(t, "lic-1", req.LicenseID)
			require.NotNil(t, req.Notification)
			assert.Equal(t, "disabled", req.Notification.Period)
			return &vscanner.Project{ID: "proj-new", Name: req.Name}, nil
		},
	}
	cmd := VScanProjectCreateCmd{Name: "my-project", License: "lic-1", Notify: "disabled"}
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
			assert.Equal(t, []string{"192.168.1.0/24"}, req.Networks)
			assert.Equal(t, []string{"1-1000"}, req.Ports)
			return &vscanner.Task{ID: "task-1", ProjectID: projectID, Name: req.Name}, nil
		},
	}
	cmd := VScanTaskCreateCmd{
		ProjectID: "proj-1",
		Name:      "scan-task",
		Networks:  []string{"192.168.1.0/24"},
		Ports:     []string{"1-1000"},
		Timing:    "normal",
		Enabled:   true,
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

func TestVScanProjectStatsCmd_JSONEnvelope(t *testing.T) {
	client := &mockVScannerClient{
		projectStatisticsFn: func(_ context.Context, projectID string, stats []string) (map[string]json.RawMessage, error) {
			assert.Equal(t, "proj-1", projectID)
			assert.Equal(t, []string{vscanner.StatTotalHosts}, stats)
			return map[string]json.RawMessage{vscanner.StatTotalHosts: json.RawMessage(`10`)}, nil
		},
	}
	cmd := VScanProjectStatsCmd{ProjectID: "proj-1", Stat: []string{vscanner.StatTotalHosts}}
	out := captureStdout(t, func() {
		err := cmd.Run(context.Background(), jsonCLI(), vscanDeps(client))
		require.NoError(t, err)
	})
	var envelope IntelOutput
	require.NoError(t, json.Unmarshal(out, &envelope))
	assert.Equal(t, "vscan project stats", envelope.Command)
}

func TestVScanLicenseCmd_JSONEnvelope(t *testing.T) {
	client := &mockVScannerClient{
		getLicensesFn: func(_ context.Context) ([]vscanner.License, error) {
			return []vscanner.License{{ID: "lic-1", Type: "enterprise"}}, nil
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
