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

func TestSearchCmd_JSONEnvelope(t *testing.T) {
	client := &mockIntelClient{
		searchFn: func(_ context.Context, _ string, _, _ int) (*intel.SearchResult, error) {
			return &intel.SearchResult{Total: 1, Bulletins: []vulners.Bulletin{{ID: "CVE-2021-44228"}}}, nil
		},
	}

	cmd := SearchCmd{Query: "log4j", Limit: 10}
	out := captureStdout(t, func() {
		err := cmd.Run(context.Background(), jsonCLI(), testDeps(client), nopStore())
		require.NoError(t, err)
	})

	var envelope IntelOutput
	require.NoError(t, json.Unmarshal(out, &envelope))
	assert.Equal(t, "1.0.0", envelope.SchemaVersion)
	assert.Equal(t, "search", envelope.Command)
	assert.NotNil(t, envelope.Data)
}

func TestCVECmd_JSONEnvelope(t *testing.T) {
	client := &mockIntelClient{
		getBulletinFn: func(_ context.Context, id string) (*vulners.Bulletin, error) {
			return &vulners.Bulletin{ID: id}, nil
		},
	}

	cmd := CVECmd{ID: "CVE-2021-44228"}
	out := captureStdout(t, func() {
		err := cmd.Run(context.Background(), jsonCLI(), testDeps(client), nopStore())
		require.NoError(t, err)
	})

	var envelope IntelOutput
	require.NoError(t, json.Unmarshal(out, &envelope))
	assert.Equal(t, "1.0.0", envelope.SchemaVersion)
	assert.Equal(t, "cve", envelope.Command)
}

func TestSearchCmd_TableNoEnvelope(t *testing.T) {
	client := &mockIntelClient{
		searchFn: func(_ context.Context, _ string, _, _ int) (*intel.SearchResult, error) {
			return &intel.SearchResult{Total: 1, Bulletins: []vulners.Bulletin{{ID: "CVE-2021-44228"}}}, nil
		},
	}

	cmd := SearchCmd{Query: "log4j", Limit: 10}
	out := captureStdout(t, func() {
		err := cmd.Run(context.Background(), tableCLI(), testDeps(client), nopStore())
		require.NoError(t, err)
	})

	// Table output should NOT be a JSON envelope.
	var envelope IntelOutput
	err := json.Unmarshal(out, &envelope)
	// Either fails to parse or doesn't have schemaVersion.
	if err == nil {
		assert.Empty(t, envelope.SchemaVersion, "table output should not have envelope")
	}
}

func TestStixCmd_JSONEnvelope(t *testing.T) {
	client := &mockIntelClient{
		makeSTIXBundleByIDFn: func(_ context.Context, _ string) (*vulners.StixBundle, error) {
			return &vulners.StixBundle{}, nil
		},
	}

	cmd := StixCmd{ID: "TEST-123"}
	out := captureStdout(t, func() {
		err := cmd.Run(context.Background(), jsonCLI(), testDeps(client))
		require.NoError(t, err)
	})

	var envelope IntelOutput
	require.NoError(t, json.Unmarshal(out, &envelope))
	assert.Equal(t, "stix", envelope.Command)
}
