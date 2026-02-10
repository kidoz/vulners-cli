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

	var info VersionInfo
	require.NoError(t, json.Unmarshal(out, &info))
	assert.NotEmpty(t, info.GoVersion)
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
