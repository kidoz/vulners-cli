package cmd

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	vulners "github.com/kidoz/go-vulners"
)

func TestWebhookListCmd_JSONEnvelope(t *testing.T) {
	client := &mockIntelClient{
		listWebhooksFn: func(_ context.Context) ([]vulners.Webhook, error) {
			return []vulners.Webhook{{ID: "wh-1", Query: "type:cve", Active: true}}, nil
		},
	}
	cmd := WebhookListCmd{}
	out := captureStdout(t, func() {
		err := cmd.Run(context.Background(), jsonCLI(), testDeps(client))
		require.NoError(t, err)
	})
	var envelope IntelOutput
	require.NoError(t, json.Unmarshal(out, &envelope))
	assert.Equal(t, "webhook list", envelope.Command)
}

func TestWebhookAddCmd_JSONEnvelope(t *testing.T) {
	client := &mockIntelClient{
		addWebhookFn: func(_ context.Context, query string) (*vulners.Webhook, error) {
			return &vulners.Webhook{ID: "wh-new", Query: query}, nil
		},
	}
	cmd := WebhookAddCmd{Query: "type:cve AND cvss.score:[9 TO 10]"}
	out := captureStdout(t, func() {
		err := cmd.Run(context.Background(), jsonCLI(), testDeps(client))
		require.NoError(t, err)
	})
	var envelope IntelOutput
	require.NoError(t, json.Unmarshal(out, &envelope))
	assert.Equal(t, "webhook add", envelope.Command)
}

func TestWebhookReadCmd_JSONEnvelope(t *testing.T) {
	client := &mockIntelClient{
		readWebhookFn: func(_ context.Context, _ string, _ bool) (*vulners.WebhookData, error) {
			return &vulners.WebhookData{ID: "wh-1", NewCount: 5}, nil
		},
	}
	cmd := WebhookReadCmd{ID: "wh-1", NewestOnly: true}
	out := captureStdout(t, func() {
		err := cmd.Run(context.Background(), jsonCLI(), testDeps(client))
		require.NoError(t, err)
	})
	var envelope IntelOutput
	require.NoError(t, json.Unmarshal(out, &envelope))
	assert.Equal(t, "webhook read", envelope.Command)
}

func TestWebhookDeleteCmd_JSONEnvelope(t *testing.T) {
	client := &mockIntelClient{}
	cmd := WebhookDeleteCmd{ID: "wh-1"}
	out := captureStdout(t, func() {
		err := cmd.Run(context.Background(), jsonCLI(), testDeps(client))
		require.NoError(t, err)
	})
	var envelope IntelOutput
	require.NoError(t, json.Unmarshal(out, &envelope))
	assert.Equal(t, "webhook delete", envelope.Command)
}

func TestWebhookCmd_NoAPIKey(t *testing.T) {
	cmd := WebhookListCmd{}
	err := cmd.Run(context.Background(), jsonCLI(), nilDeps())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "VULNERS_API_KEY")
}
