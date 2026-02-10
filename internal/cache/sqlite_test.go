package cache

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	vulners "github.com/kidoz/go-vulners"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func testStore(t *testing.T) *SQLiteStore {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "test.db")
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	store, err := NewSQLiteStore(dbPath, logger)
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.Close() })
	return store
}

func TestSQLiteStore_PutAndGetBulletin(t *testing.T) {
	store := testStore(t)
	ctx := context.Background()

	bulletins := []vulners.Bulletin{
		{ID: "CVE-2021-44228", Title: "Log4Shell"},
		{ID: "CVE-2023-0001", Title: "Test Vuln"},
	}

	err := store.PutBulletins(ctx, "cve", bulletins)
	require.NoError(t, err)

	got, err := store.GetBulletin(ctx, "CVE-2021-44228")
	require.NoError(t, err)
	assert.Equal(t, "CVE-2021-44228", got.ID)
	assert.Equal(t, "Log4Shell", got.Title)
}

func TestSQLiteStore_GetBulletin_NotFound(t *testing.T) {
	store := testStore(t)
	ctx := context.Background()

	_, err := store.GetBulletin(ctx, "CVE-NONEXISTENT")
	assert.ErrorIs(t, err, ErrOfflineDataMissing)
}

func TestSQLiteStore_SearchBulletins(t *testing.T) {
	store := testStore(t)
	ctx := context.Background()

	bulletins := []vulners.Bulletin{
		{ID: "CVE-2021-44228", Title: "Apache Log4j Log4Shell"},
		{ID: "CVE-2023-0001", Title: "Some other vuln"},
		{ID: "CVE-2023-0002", Title: "Log4j related issue"},
	}
	require.NoError(t, store.PutBulletins(ctx, "cve", bulletins))

	results, total, err := store.SearchBulletins(ctx, "Log4", 10, 0)
	require.NoError(t, err)
	assert.Equal(t, 2, total)
	assert.Len(t, results, 2)
}

func TestSQLiteStore_SearchBulletins_WildcardEscape(t *testing.T) {
	store := testStore(t)
	ctx := context.Background()

	bulletins := []vulners.Bulletin{
		{ID: "CVE-2021-44228", Title: "100% critical vuln"},
		{ID: "CVE-2023-0001", Title: "some_other_vuln"},
		{ID: "CVE-2023-0002", Title: "normal title"},
	}
	require.NoError(t, store.PutBulletins(ctx, "cve", bulletins))

	// Searching for literal "%" should only match the title containing "%"
	results, total, err := store.SearchBulletins(ctx, "100%", 10, 0)
	require.NoError(t, err)
	assert.Equal(t, 1, total)
	assert.Len(t, results, 1)

	// Searching for literal "_" should only match the title containing "_"
	results, total, err = store.SearchBulletins(ctx, "some_other", 10, 0)
	require.NoError(t, err)
	assert.Equal(t, 1, total)
	assert.Len(t, results, 1)
}

func TestSQLiteStore_CollectionMeta(t *testing.T) {
	store := testStore(t)
	ctx := context.Background()

	bulletins := []vulners.Bulletin{
		{ID: "CVE-2021-44228", Title: "Test"},
	}
	require.NoError(t, store.PutBulletins(ctx, "cve", bulletins))

	metas, err := store.GetCollectionMeta(ctx)
	require.NoError(t, err)
	require.Len(t, metas, 1)
	assert.Equal(t, "cve", metas[0].Collection)
	assert.Equal(t, 1, metas[0].Count)
}

func TestSQLiteStore_GetLastSyncTime(t *testing.T) {
	store := testStore(t)
	ctx := context.Background()

	// No data yet — should return zero time.
	syncTime, err := store.GetLastSyncTime(ctx, "cve")
	require.NoError(t, err)
	assert.True(t, syncTime.IsZero())

	// Put bulletins to create collection_meta entry.
	bulletins := []vulners.Bulletin{
		{ID: "CVE-2021-44228", Title: "Log4Shell"},
	}
	require.NoError(t, store.PutBulletins(ctx, "cve", bulletins))

	syncTime, err = store.GetLastSyncTime(ctx, "cve")
	require.NoError(t, err)
	assert.False(t, syncTime.IsZero())
	assert.WithinDuration(t, time.Now(), syncTime, 5*time.Second)
}

func TestSQLiteStore_Purge(t *testing.T) {
	store := testStore(t)
	ctx := context.Background()

	bulletins := []vulners.Bulletin{
		{ID: "CVE-2021-44228", Title: "Test"},
	}
	require.NoError(t, store.PutBulletins(ctx, "cve", bulletins))
	require.NoError(t, store.Purge(ctx))

	_, err := store.GetBulletin(ctx, "CVE-2021-44228")
	assert.ErrorIs(t, err, ErrOfflineDataMissing)

	metas, err := store.GetCollectionMeta(ctx)
	require.NoError(t, err)
	assert.Empty(t, metas)
}
