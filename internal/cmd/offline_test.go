package cmd

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/kidoz/vulners-cli/internal/cache"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestOfflineStatusCmd_Happy(t *testing.T) {
	store := &mockStore{
		getCollectionMetaFn: func(context.Context) ([]cache.CollectionMeta, error) {
			return []cache.CollectionMeta{
				{Collection: "cve", Count: 100, SyncedAt: time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)},
			}, nil
		},
	}

	cmd := OfflineStatusCmd{}
	out := captureStdout(t, func() {
		err := cmd.Run(context.Background(), jsonCLI(), store)
		require.NoError(t, err)
	})
	assert.Contains(t, string(out), "cve")
}

func TestOfflineStatusCmd_Empty(t *testing.T) {
	store := &mockStore{
		getCollectionMetaFn: func(context.Context) ([]cache.CollectionMeta, error) {
			return []cache.CollectionMeta{}, nil
		},
	}

	cmd := OfflineStatusCmd{}
	// empty metas should not error — it prints a message to stderr
	err := cmd.Run(context.Background(), jsonCLI(), store)
	require.NoError(t, err)
}

func TestOfflineStatusCmd_Error(t *testing.T) {
	store := &mockStore{} // defaults to ErrOfflineDataMissing

	cmd := OfflineStatusCmd{}
	err := cmd.Run(context.Background(), jsonCLI(), store)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "getting offline status")
}

func TestOfflinePurgeCmd_Happy(t *testing.T) {
	called := false
	store := &mockStore{
		purgeFn: func(context.Context) error {
			called = true
			return nil
		},
	}

	cmd := OfflinePurgeCmd{}
	err := cmd.Run(context.Background(), store, discardLogger())
	require.NoError(t, err)
	assert.True(t, called)
}

func TestOfflinePurgeCmd_Error(t *testing.T) {
	store := &mockStore{
		purgeFn: func(context.Context) error {
			return fmt.Errorf("disk full")
		},
	}

	cmd := OfflinePurgeCmd{}
	err := cmd.Run(context.Background(), store, discardLogger())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "purging offline database")
}
