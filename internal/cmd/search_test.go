package cmd

import (
	"context"
	"fmt"
	"testing"

	"github.com/kidoz/vulners-cli/internal/intel"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	vulners "github.com/kidoz/go-vulners"
)

func TestSearchCmd_Happy(t *testing.T) {
	client := &mockIntelClient{
		searchFn: func(_ context.Context, query string, limit, offset int) (*intel.SearchResult, error) {
			assert.Equal(t, "log4j", query)
			assert.Equal(t, 10, limit)
			return &intel.SearchResult{Total: 1, Bulletins: []vulners.Bulletin{{ID: "CVE-2021-44228"}}}, nil
		},
	}

	cmd := SearchCmd{Query: "log4j", Limit: 10}
	out := captureStdout(t, func() {
		err := cmd.Run(context.Background(), jsonCLI(), testDeps(client), nopStore())
		require.NoError(t, err)
	})
	assert.Contains(t, string(out), "CVE-2021-44228")
}

func TestSearchCmd_ExploitsFlag(t *testing.T) {
	called := false
	client := &mockIntelClient{
		searchExploitsFn: func(_ context.Context, _ string, _, _ int) (*intel.SearchResult, error) {
			called = true
			return &intel.SearchResult{}, nil
		},
	}

	cmd := SearchCmd{Query: "test", Limit: 10, Exploits: true}
	captureStdout(t, func() {
		err := cmd.Run(context.Background(), jsonCLI(), testDeps(client), nopStore())
		require.NoError(t, err)
	})
	assert.True(t, called, "SearchExploits should have been called")
}

func TestSearchCmd_NilIntel(t *testing.T) {
	cmd := SearchCmd{Query: "test", Limit: 10}
	err := cmd.Run(context.Background(), jsonCLI(), nilDeps(), nopStore())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "VULNERS_API_KEY")
}

func TestSearchCmd_Offline(t *testing.T) {
	store := &mockStore{
		searchBulletinsFn: func(_ context.Context, query string, limit, offset int) ([]vulners.Bulletin, int, error) {
			return []vulners.Bulletin{{ID: "OFFLINE-1"}}, 1, nil
		},
	}

	cmd := SearchCmd{Query: "test", Limit: 10}
	out := captureStdout(t, func() {
		err := cmd.Run(context.Background(), offlineCLI(), nilDeps(), store)
		require.NoError(t, err)
	})
	assert.Contains(t, string(out), "OFFLINE-1")
}

func TestSearchCmd_OfflineError(t *testing.T) {
	store := &mockStore{} // defaults to ErrOfflineDataMissing

	cmd := SearchCmd{Query: "test", Limit: 10}
	err := cmd.Run(context.Background(), offlineCLI(), nilDeps(), store)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "offline search failed")
}

func TestSearchCmd_APIError(t *testing.T) {
	client := &mockIntelClient{
		searchFn: func(context.Context, string, int, int) (*intel.SearchResult, error) {
			return nil, fmt.Errorf("connection refused")
		},
	}

	cmd := SearchCmd{Query: "test", Limit: 10}
	err := cmd.Run(context.Background(), jsonCLI(), testDeps(client), nopStore())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "search failed")
}

func TestSearchCmd_SarifRejected(t *testing.T) {
	cmd := SearchCmd{Query: "test", Limit: 10}
	err := cmd.Run(context.Background(), sarifCLI(), testDeps(&mockIntelClient{}), nopStore())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "only supported for scan commands")
}
