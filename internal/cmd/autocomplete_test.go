package cmd

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAutocompleteCmd_JSONEnvelope(t *testing.T) {
	client := &mockIntelClient{
		queryAutocompleteFn: func(_ context.Context, query string) ([]string, error) {
			return []string{"apache log4j", "apache logging"}, nil
		},
	}

	cmd := AutocompleteCmd{Query: "apache log"}
	out := captureStdout(t, func() {
		err := cmd.Run(context.Background(), jsonCLI(), testDeps(client))
		require.NoError(t, err)
	})

	var envelope IntelOutput
	require.NoError(t, json.Unmarshal(out, &envelope))
	assert.Equal(t, "1.0.0", envelope.SchemaVersion)
	assert.Equal(t, "autocomplete", envelope.Command)

	suggestions, ok := envelope.Data.([]any)
	require.True(t, ok, "data should be an array")
	assert.Len(t, suggestions, 2)
	assert.Equal(t, "apache log4j", suggestions[0])
}

func TestAutocompleteCmd_OfflineError(t *testing.T) {
	cli := jsonCLI()
	cli.Offline = true

	cmd := AutocompleteCmd{Query: "test"}
	err := cmd.Run(context.Background(), cli, testDeps(&mockIntelClient{}))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "offline")
}

func TestAutocompleteCmd_NoAPIKey(t *testing.T) {
	deps := &Deps{Intel: nil}
	cmd := AutocompleteCmd{Query: "test"}
	err := cmd.Run(context.Background(), jsonCLI(), deps)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "VULNERS_API_KEY")
}
