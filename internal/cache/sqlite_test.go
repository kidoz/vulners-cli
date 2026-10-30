package cache

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
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

func TestSQLiteStore_MatchBulletins(t *testing.T) {
	store := testStore(t)
	ctx := context.Background()
	bulletins := []vulners.Bulletin{
		{ID: "CVE-MATCH", Title: "OpenSSL advisory", AffectedSoftware: []vulners.AffectedSoftware{{Name: "OpenSSL", Version: "1.0"}}},
		{ID: "CVE-OTHER-VERSION", AffectedSoftware: []vulners.AffectedSoftware{{Name: "openssl", Version: "2.0"}}},
		{ID: "CVE-CPE", AffectedSoftware: []vulners.AffectedSoftware{{CPE: "cpe:2.3:a:vendor:product:1.0"}}},
	}
	require.NoError(t, store.PutBulletins(ctx, "cve", bulletins))

	results, err := store.MatchBulletins(ctx, "openssl", "1.0", "")
	require.NoError(t, err)
	require.Len(t, results, 1)
	assert.Equal(t, "CVE-MATCH", results[0].ID)

	results, err = store.MatchBulletins(ctx, "", "", "cpe:2.3:a:vendor:product:1.0")
	require.NoError(t, err)
	require.Len(t, results, 1)
	assert.Equal(t, "CVE-CPE", results[0].ID)
}

func TestSQLiteStore_ReplaceCollectionRemovesStaleBulletins(t *testing.T) {
	store := testStore(t)
	ctx := context.Background()
	require.NoError(t, store.PutBulletins(ctx, "cve", []vulners.Bulletin{{ID: "CVE-OLD"}, {ID: "CVE-KEEP"}}))
	require.NoError(t, store.ReplaceCollection(ctx, "cve", []vulners.Bulletin{{ID: "CVE-KEEP"}}))

	_, err := store.GetBulletin(ctx, "CVE-OLD")
	assert.ErrorIs(t, err, ErrOfflineDataMissing)
	_, err = store.GetBulletin(ctx, "CVE-KEEP")
	require.NoError(t, err)
	metas, err := store.GetCollectionMeta(ctx)
	require.NoError(t, err)
	require.Len(t, metas, 1)
	assert.Equal(t, 1, metas[0].Count)
}

func TestSQLiteStore_PrivateFiles(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix permissions")
	}
	dir := filepath.Join(t.TempDir(), ".vulners")
	require.NoError(t, os.Mkdir(dir, 0o755)) //nolint:gosec // Reproduce a pre-existing permissive directory.
	require.NoError(t, os.Chmod(dir, 0o755)) //nolint:gosec // Ignore umask when reproducing permissive permissions.
	path := filepath.Join(dir, "test.db")
	store, err := NewSQLiteStore(path, slog.Default())
	require.NoError(t, err)
	defer func() { require.NoError(t, store.Close()) }()
	require.NoError(t, store.PutBulletins(context.Background(), "test", []vulners.Bulletin{{ID: "test"}}))
	info, err := os.Stat(dir)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o750), info.Mode().Perm())
	for _, suffix := range []string{"", "-wal", "-shm"} {
		info, err := os.Stat(path + suffix)
		require.NoError(t, err)
		assert.Equal(t, os.FileMode(0o600), info.Mode().Perm(), suffix)
	}
}

func TestSQLiteStore_RejectsMissingPathAndSymlinks(t *testing.T) {
	_, err := NewSQLiteStore("", slog.Default())
	require.Error(t, err)
	path := filepath.Join(t.TempDir(), "cache.db")
	target := filepath.Join(t.TempDir(), "target")
	require.NoError(t, os.WriteFile(target, []byte("preserve"), 0o600))
	require.NoError(t, os.Symlink(target, path))
	_, err = NewSQLiteStore(path, slog.Default())
	require.Error(t, err)
	data, err := os.ReadFile(target)
	require.NoError(t, err)
	assert.Equal(t, "preserve", string(data))
}

func TestSQLiteStore_EmptyAffectedVersionDoesNotMatch(t *testing.T) {
	store := testStore(t)
	ctx := context.Background()
	require.NoError(t, store.PutBulletins(ctx, "test", []vulners.Bulletin{{ID: "unknown", AffectedSoftware: []vulners.AffectedSoftware{{Name: "pkg"}}}}))
	results, err := store.MatchBulletins(ctx, "pkg", "1.0", "")
	require.NoError(t, err)
	assert.Empty(t, results)
}

func TestSQLiteStore_MatchesVersionRanges(t *testing.T) {
	store := testStore(t)
	ctx := context.Background()
	require.NoError(t, store.PutBulletins(ctx, "test", []vulners.Bulletin{
		{ID: "LOWER", AffectedSoftware: []vulners.AffectedSoftware{{Name: "pkg", Version: "1.0", Operator: "le"}}},
		{ID: "HIGHER", AffectedSoftware: []vulners.AffectedSoftware{{Name: "pkg", Version: "1.0", Operator: "ge"}}},
	}))
	for _, tc := range []struct {
		version string
		ids     []string
	}{{"0.9", []string{"LOWER"}}, {"1.0", []string{"HIGHER", "LOWER"}}, {"1.1", []string{"HIGHER"}}} {
		results, err := store.MatchBulletins(ctx, "pkg", tc.version, "")
		require.NoError(t, err)
		var ids []string
		for _, b := range results {
			ids = append(ids, b.ID)
		}
		assert.Equal(t, tc.ids, ids)
	}
}

func TestSQLiteStore_UnsupportedRangeFailsLookup(t *testing.T) {
	store := testStore(t)
	ctx := context.Background()
	require.NoError(t, store.PutBulletins(ctx, "test", []vulners.Bulletin{{ID: "INVALID", AffectedSoftware: []vulners.AffectedSoftware{{Name: "pkg", Version: "release-final", Operator: "le"}}}}))
	results, err := store.MatchBulletins(ctx, "pkg", "1.0", "")
	require.Error(t, err)
	assert.Empty(t, results)
}
