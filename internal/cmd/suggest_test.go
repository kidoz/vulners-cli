package cmd

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSuggestCmd_JSONEnvelope(t *testing.T) {
	client := &mockIntelClient{
		getSuggestionFn: func(_ context.Context, field string) ([]string, error) {
			return []string{"cve", "exploit", "advisory"}, nil
		},
	}

	cmd := SuggestCmd{Field: "type"}
	out := captureStdout(t, func() {
		err := cmd.Run(context.Background(), jsonCLI(), testDeps(client))
		require.NoError(t, err)
	})

	var envelope IntelOutput
	require.NoError(t, json.Unmarshal(out, &envelope))
	assert.Equal(t, "1.0.0", envelope.SchemaVersion)
	assert.Equal(t, "suggest", envelope.Command)

	suggestions, ok := envelope.Data.([]any)
	require.True(t, ok, "data should be an array")
	assert.Len(t, suggestions, 3)
	assert.Equal(t, "cve", suggestions[0])
}

func TestSuggestCmd_OfflineError(t *testing.T) {
	cli := jsonCLI()
	cli.Offline = true

	cmd := SuggestCmd{Field: "type"}
	err := cmd.Run(context.Background(), cli, testDeps(&mockIntelClient{}))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "offline")
}

func TestSuggestCmd_NoAPIKey(t *testing.T) {
	deps := &Deps{Intel: nil}
	cmd := SuggestCmd{Field: "type"}
	err := cmd.Run(context.Background(), jsonCLI(), deps)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "VULNERS_API_KEY")
}
