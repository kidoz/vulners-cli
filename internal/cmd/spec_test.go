package cmd

import (
	"encoding/json"
	"testing"

	"github.com/alecthomas/kong"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func testKong(t *testing.T) *kong.Kong {
	t.Helper()
	var cli CLI
	k, err := kong.New(&cli,
		kong.Name("vulners"),
		kong.Exit(func(_ int) {}),
	)
	require.NoError(t, err)
	return k
}

func TestSpecCmd_JSONOutput(t *testing.T) {
	k := testKong(t)

	cmd := SpecCmd{}
	out := captureStdout(t, func() {
		err := cmd.Run(jsonCLI(), k)
		require.NoError(t, err)
	})

	var envelope IntelOutput
	require.NoError(t, json.Unmarshal(out, &envelope))
	assert.Equal(t, "1.0.0", envelope.SchemaVersion)
	assert.Equal(t, "spec", envelope.Command)

	data, err := json.Marshal(envelope.Data)
	require.NoError(t, err)

	var spec SpecOutput
	require.NoError(t, json.Unmarshal(data, &spec))

	// Should have global flags.
	assert.NotEmpty(t, spec.Globals, "should have global flags")

	// Should have commands.
	assert.NotEmpty(t, spec.Commands, "should have commands")

	// Find the search command and verify it has expected structure.
	var searchCmd *SpecCommand
	for i, c := range spec.Commands {
		if c.Name == "search" {
			searchCmd = &spec.Commands[i]
			break
		}
	}
	require.NotNil(t, searchCmd, "search command should exist")
	assert.NotEmpty(t, searchCmd.Help)
}

func TestSpecCmd_HasAllTopLevelCommands(t *testing.T) {
	k := testKong(t)

	cmd := SpecCmd{}
	out := captureStdout(t, func() {
		err := cmd.Run(jsonCLI(), k)
		require.NoError(t, err)
	})

	var envelope IntelOutput
	require.NoError(t, json.Unmarshal(out, &envelope))

	data, err := json.Marshal(envelope.Data)
	require.NoError(t, err)

	var spec SpecOutput
	require.NoError(t, json.Unmarshal(data, &spec))

	names := make(map[string]bool)
	for _, c := range spec.Commands {
		names[c.Name] = true
	}

	expected := []string{"version", "search", "cve", "cpe", "audit", "scan", "offline", "stix", "autocomplete", "suggest", "doctor", "spec"}
	for _, name := range expected {
		assert.True(t, names[name], "missing command: %s", name)
	}
}

func TestSpecCmd_GlobalFlags(t *testing.T) {
	k := testKong(t)

	cmd := SpecCmd{}
	out := captureStdout(t, func() {
		err := cmd.Run(jsonCLI(), k)
		require.NoError(t, err)
	})

	var envelope IntelOutput
	require.NoError(t, json.Unmarshal(out, &envelope))

	data, err := json.Marshal(envelope.Data)
	require.NoError(t, err)

	var spec SpecOutput
	require.NoError(t, json.Unmarshal(data, &spec))

	flagNames := make(map[string]bool)
	for _, f := range spec.Globals {
		flagNames[f.Name] = true
	}

	// Check key global flags are present.
	assert.True(t, flagNames["output"], "missing --output flag")
	assert.True(t, flagNames["agent"], "missing --agent flag")
	assert.True(t, flagNames["quiet"], "missing --quiet flag")
}
