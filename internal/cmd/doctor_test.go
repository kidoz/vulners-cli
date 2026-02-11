package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/kidoz/vulners-cli/internal/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDoctorCmd_AllPass(t *testing.T) {
	client := &mockIntelClient{
		queryAutocompleteFn: func(_ context.Context, _ string) ([]string, error) {
			return []string{"ok"}, nil
		},
	}

	cmd := DoctorCmd{}
	out := captureStdout(t, func() {
		err := cmd.Run(context.Background(), jsonCLI(), testDeps(client), nopStore())
		require.NoError(t, err)
	})

	var envelope IntelOutput
	require.NoError(t, json.Unmarshal(out, &envelope))
	assert.Equal(t, "doctor", envelope.Command)

	data, err := json.Marshal(envelope.Data)
	require.NoError(t, err)

	var doctorOut DoctorOutput
	require.NoError(t, json.Unmarshal(data, &doctorOut))
	assert.True(t, doctorOut.AllPass)
	assert.GreaterOrEqual(t, len(doctorOut.Checks), 4)
}

func TestDoctorCmd_NoAPIKey(t *testing.T) {
	cmd := DoctorCmd{}
	out := captureStdout(t, func() {
		err := cmd.Run(context.Background(), jsonCLI(), nilDeps(), nopStore())
		// Should return exit code 2 (usage error) because API key check fails.
		var exitErr *model.ExitError
		require.ErrorAs(t, err, &exitErr)
		assert.Equal(t, model.ExitUsageError, exitErr.Code)
	})

	var envelope IntelOutput
	require.NoError(t, json.Unmarshal(out, &envelope))

	data, err := json.Marshal(envelope.Data)
	require.NoError(t, err)

	var doctorOut DoctorOutput
	require.NoError(t, json.Unmarshal(data, &doctorOut))
	assert.False(t, doctorOut.AllPass)

	// Find the api_key check.
	var apiCheck CheckResult
	for _, ch := range doctorOut.Checks {
		if ch.Name == "api_key" {
			apiCheck = ch
			break
		}
	}
	assert.Equal(t, "fail", apiCheck.Status)
	assert.NotEmpty(t, apiCheck.Remediation)
}

func TestDoctorCmd_NetworkError(t *testing.T) {
	client := &mockIntelClient{
		queryAutocompleteFn: func(_ context.Context, _ string) ([]string, error) {
			return nil, fmt.Errorf("connection refused")
		},
	}

	cmd := DoctorCmd{}
	out := captureStdout(t, func() {
		err := cmd.Run(context.Background(), jsonCLI(), testDeps(client), nopStore())
		var exitErr *model.ExitError
		require.ErrorAs(t, err, &exitErr)
	})

	var envelope IntelOutput
	require.NoError(t, json.Unmarshal(out, &envelope))

	data, err := json.Marshal(envelope.Data)
	require.NoError(t, err)

	var doctorOut DoctorOutput
	require.NoError(t, json.Unmarshal(data, &doctorOut))
	assert.False(t, doctorOut.AllPass)

	var netCheck CheckResult
	for _, ch := range doctorOut.Checks {
		if ch.Name == "network" {
			netCheck = ch
			break
		}
	}
	assert.Equal(t, "fail", netCheck.Status)
}
