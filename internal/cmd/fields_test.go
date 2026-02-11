package cmd

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/kidoz/vulners-cli/internal/intel"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	vulners "github.com/kidoz/go-vulners"
)

func TestProjectFields_FilterKeys(t *testing.T) {
	data := map[string]any{
		"schemaVersion": "1.0.0",
		"command":       "search",
		"data":          []string{"a", "b"},
		"meta":          nil,
	}

	result, err := projectFields(data, []string{"command", "data"})
	require.NoError(t, err)

	m, ok := result.(map[string]any)
	require.True(t, ok)
	assert.Len(t, m, 2)
	assert.Equal(t, "search", m["command"])
	assert.NotNil(t, m["data"])
}

func TestProjectFields_EmptyFields(t *testing.T) {
	data := map[string]any{"a": 1, "b": 2}
	result, err := projectFields(data, nil)
	require.NoError(t, err)
	assert.Equal(t, data, result)
}

func TestProjectFields_ArrayPassthrough(t *testing.T) {
	data := []string{"a", "b", "c"}
	result, err := projectFields(data, []string{"x"})
	require.NoError(t, err)
	// Arrays can't be projected — returned as-is.
	assert.Equal(t, data, result)
}

func TestFieldsFlag_IntelOutput(t *testing.T) {
	client := &mockIntelClient{
		searchFn: func(_ context.Context, _ string, _, _ int) (*intel.SearchResult, error) {
			return &intel.SearchResult{Total: 1, Bulletins: []vulners.Bulletin{{ID: "CVE-2021-44228"}}}, nil
		},
	}

	cli := jsonCLI()
	cli.Fields = []string{"command", "data"}

	cmd := SearchCmd{Query: "log4j", Limit: 10}
	out := captureStdout(t, func() {
		err := cmd.Run(context.Background(), cli, testDeps(client), nopStore())
		require.NoError(t, err)
	})

	var m map[string]any
	require.NoError(t, json.Unmarshal(out, &m))

	// Should have only the requested fields.
	assert.Len(t, m, 2)
	assert.Contains(t, m, "command")
	assert.Contains(t, m, "data")
	assert.NotContains(t, m, "schemaVersion")
}

func TestFieldsFlag_IgnoredForTable(t *testing.T) {
	client := &mockIntelClient{
		searchFn: func(_ context.Context, _ string, _, _ int) (*intel.SearchResult, error) {
			return &intel.SearchResult{Total: 0, Bulletins: nil}, nil
		},
	}

	cli := tableCLI()
	cli.Fields = []string{"command"} // Should be ignored for table output.

	cmd := SearchCmd{Query: "test", Limit: 10}
	out := captureStdout(t, func() {
		err := cmd.Run(context.Background(), cli, testDeps(client), nopStore())
		require.NoError(t, err)
	})

	// Table output should not be affected by --fields.
	assert.NotEmpty(t, out)
}
