package cmd

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	vulners "github.com/kidoz/go-vulners"
)

func TestSubscriptionListCmd_JSONEnvelope(t *testing.T) {
	client := &mockIntelClient{
		listSubscriptionsFn: func(_ context.Context) ([]vulners.Subscription, error) {
			return []vulners.Subscription{{ID: "sub-1", Name: "critical-cves"}}, nil
		},
	}
	cmd := SubscriptionListCmd{}
	out := captureStdout(t, func() {
		err := cmd.Run(context.Background(), jsonCLI(), testDeps(client))
		require.NoError(t, err)
	})
	var envelope IntelOutput
	require.NoError(t, json.Unmarshal(out, &envelope))
	assert.Equal(t, "subscription list", envelope.Command)
}

func TestSubscriptionCreateCmd_JSONEnvelope(t *testing.T) {
	client := &mockIntelClient{
		createSubscriptionFn: func(_ context.Context, req *vulners.SubscriptionRequest) (*vulners.Subscription, error) {
			return &vulners.Subscription{ID: "sub-new", Name: req.Name, Query: req.Query}, nil
		},
	}
	cmd := SubscriptionCreateCmd{Name: "test", Type: "alert", Query: "type:cve"}
	out := captureStdout(t, func() {
		err := cmd.Run(context.Background(), jsonCLI(), testDeps(client))
		require.NoError(t, err)
	})
	var envelope IntelOutput
	require.NoError(t, json.Unmarshal(out, &envelope))
	assert.Equal(t, "subscription create", envelope.Command)
}

func TestSubscriptionGetCmd_JSONEnvelope(t *testing.T) {
	client := &mockIntelClient{
		getSubscriptionFn: func(_ context.Context, id string) (*vulners.Subscription, error) {
			return &vulners.Subscription{ID: id, Name: "test"}, nil
		},
	}
	cmd := SubscriptionGetCmd{ID: "sub-1"}
	out := captureStdout(t, func() {
		err := cmd.Run(context.Background(), jsonCLI(), testDeps(client))
		require.NoError(t, err)
	})
	var envelope IntelOutput
	require.NoError(t, json.Unmarshal(out, &envelope))
	assert.Equal(t, "subscription get", envelope.Command)
}

func TestSubscriptionDeleteCmd_JSONEnvelope(t *testing.T) {
	client := &mockIntelClient{}
	cmd := SubscriptionDeleteCmd{ID: "sub-1"}
	out := captureStdout(t, func() {
		err := cmd.Run(context.Background(), jsonCLI(), testDeps(client))
		require.NoError(t, err)
	})
	var envelope IntelOutput
	require.NoError(t, json.Unmarshal(out, &envelope))
	assert.Equal(t, "subscription delete", envelope.Command)
}

func TestSubscriptionCmd_NoAPIKey(t *testing.T) {
	cmd := SubscriptionListCmd{}
	err := cmd.Run(context.Background(), jsonCLI(), nilDeps())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "VULNERS_API_KEY")
}
