//go:build unix

package cache

import (
	"context"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	vulners "github.com/kidoz/go-vulners"
	"github.com/stretchr/testify/require"
)

func TestSQLiteStore_SidecarCreationPermissions(t *testing.T) {
	if os.Getenv("VULNERS_TEST_SIDECAR_HELPER") == "" {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		binary, err := os.Executable()
		require.NoError(t, err)
		child := exec.CommandContext(ctx, binary, "-test.run=^TestSQLiteStore_SidecarCreationPermissions$", "-test.v") //nolint:gosec // Runs this test binary from os.Executable to isolate umask changes.
		child.Env = append(os.Environ(), "VULNERS_TEST_SIDECAR_HELPER=1")
		output, err := child.CombinedOutput()
		require.NoError(t, err, "%s", output)
		t.Logf("isolated umask test:\n%s", output)
		return
	}
	// Process-wide umask changes are confined to this dedicated subprocess.
	syscall.Umask(0)
	for _, dirname := range []string{".vulners", "custom-cache"} {
		t.Run(dirname, func(t *testing.T) { checkSidecarRecreation(t, dirname) })
	}
}

func checkSidecarRecreation(t *testing.T, dirname string) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), dirname)
	require.NoError(t, os.Mkdir(dir, 0o775)) //nolint:gosec // Exercise a group-accessible parent with a permissive umask.
	path := filepath.Join(dir, "test.db")
	for generation := range 2 {
		for _, suffix := range []string{"-wal", "-shm"} {
			_, err := os.Stat(path + suffix)
			require.True(t, os.IsNotExist(err), "sidecar must be absent before SQLite creates it")
		}
		store, err := NewSQLiteStore(path, slog.Default())
		require.NoError(t, err)
		require.NoError(t, store.PutBulletins(context.Background(), "test", []vulners.Bulletin{{ID: "test"}}))
		for _, suffix := range []string{"", "-wal", "-shm"} {
			info, err := os.Stat(path + suffix)
			require.NoError(t, err)
			t.Logf("generation %d: %s mode %04o", generation, suffix, info.Mode().Perm())
			require.Equal(t, os.FileMode(0o600), info.Mode().Perm(), suffix)
		}
		require.NoError(t, store.Close())
	}
}
