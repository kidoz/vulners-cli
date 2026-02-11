package cmd

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestVersionCmd_JSON(t *testing.T) {
	cmd := VersionCmd{}
	out := captureStdout(t, func() {
		err := cmd.Run(jsonCLI())
		require.NoError(t, err)
	})

	var envelope IntelOutput
	require.NoError(t, json.Unmarshal(out, &envelope))
	assert.Equal(t, "1.0.0", envelope.SchemaVersion)
	assert.Equal(t, "version", envelope.Command)

	data, ok := envelope.Data.(map[string]any)
	require.True(t, ok)
	assert.NotEmpty(t, data["goVersion"])
}

func TestVersionCmd_Table(t *testing.T) {
	cmd := VersionCmd{}
	out := captureStdout(t, func() {
		err := cmd.Run(tableCLI())
		require.NoError(t, err)
	})
	assert.Contains(t, string(out), "vulners")
}

func TestVersionCmd_SarifRejected(t *testing.T) {
	cmd := VersionCmd{}
	err := cmd.Run(sarifCLI())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "only supported for scan commands")
}
