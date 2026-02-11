package cmd

import (
	"encoding/json"
	"testing"

	"github.com/kidoz/vulners-cli/internal/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWritePlanOutput_OnlineMode(t *testing.T) {
	cli := jsonCLI()
	cli.Plan = true

	components := []model.Component{
		{Name: "log4j", Version: "2.14.0", Type: "maven"},
		{Name: "express", Version: "4.17.1", Type: "npm"},
		{Name: "flask", Version: "2.0.0", Type: "pip"},
		{Name: "another-jar", Version: "1.0.0", Type: "maven"},
	}

	out := captureStdout(t, func() {
		err := writePlanOutput(cli, "/tmp/repo", components, testDeps(&mockIntelClient{}))
		require.NoError(t, err)
	})

	var envelope IntelOutput
	require.NoError(t, json.Unmarshal(out, &envelope))
	assert.Equal(t, "plan", envelope.Command)

	data, err := json.Marshal(envelope.Data)
	require.NoError(t, err)

	var plan PlanOutput
	require.NoError(t, json.Unmarshal(data, &plan))

	assert.Equal(t, "/tmp/repo", plan.Target)
	assert.Equal(t, "online", plan.Mode)
	assert.Equal(t, 4, plan.ComponentCount)
	assert.True(t, plan.HasAPIKey)
	assert.Equal(t, 2, plan.Ecosystems["maven"])
	assert.Equal(t, 1, plan.Ecosystems["npm"])
	assert.Equal(t, 1, plan.Ecosystems["pip"])
}

func TestWritePlanOutput_OfflineMode(t *testing.T) {
	cli := jsonCLI()
	cli.Plan = true
	cli.Offline = true

	components := []model.Component{
		{Name: "pkg", Version: "1.0", Type: "go"},
	}

	out := captureStdout(t, func() {
		err := writePlanOutput(cli, ".", components, nilDeps())
		require.NoError(t, err)
	})

	var envelope IntelOutput
	require.NoError(t, json.Unmarshal(out, &envelope))

	data, err := json.Marshal(envelope.Data)
	require.NoError(t, err)

	var plan PlanOutput
	require.NoError(t, json.Unmarshal(data, &plan))

	assert.Equal(t, "offline", plan.Mode)
	assert.False(t, plan.HasAPIKey)
	assert.Equal(t, 1, plan.Ecosystems["go"])
}

func TestWritePlanOutput_EmptyComponents(t *testing.T) {
	cli := jsonCLI()
	cli.Plan = true

	out := captureStdout(t, func() {
		err := writePlanOutput(cli, "/empty", nil, testDeps(&mockIntelClient{}))
		require.NoError(t, err)
	})

	var envelope IntelOutput
	require.NoError(t, json.Unmarshal(out, &envelope))

	data, err := json.Marshal(envelope.Data)
	require.NoError(t, err)

	var plan PlanOutput
	require.NoError(t, json.Unmarshal(data, &plan))

	assert.Equal(t, 0, plan.ComponentCount)
	assert.Empty(t, plan.Ecosystems)
}
