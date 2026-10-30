package inventory

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kidoz/vulners-cli/internal/scanbudget"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestManifestFileLimits(t *testing.T) {
	for _, name := range []string{"go.mod", "requirements.txt"} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), name)
			f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY, 0o600)
			require.NoError(t, err)
			require.NoError(t, f.Truncate(maxInputFileSize+1))
			require.NoError(t, f.Close())
			var collector Collector = &PipCollector{}
			if name == "go.mod" {
				collector = &GoModCollector{}
			}
			components, err := collector.Collect(context.Background(), path)
			require.ErrorIs(t, err, ErrInputLimit)
			assert.Nil(t, components)
		})
	}
}

func TestManifestComponentLimits(t *testing.T) {
	for _, name := range []string{"go.mod", "requirements.txt"} {
		for _, extra := range []int{0, 1} {
			t.Run(fmt.Sprintf("%s/%d", name, extra), func(t *testing.T) {
				var data strings.Builder
				for i := range scanbudget.MaxComponents + extra {
					if name == "go.mod" {
						fmt.Fprintf(&data, "require example.com/pkg%d v1.0.0\n", i)
					} else {
						fmt.Fprintf(&data, "pkg%d==1.0.0\n", i)
					}
				}
				path := filepath.Join(t.TempDir(), name)
				require.NoError(t, os.WriteFile(path, []byte(data.String()), 0o600))
				var collector Collector = &PipCollector{}
				if name == "go.mod" {
					collector = &GoModCollector{}
				}
				components, err := collector.Collect(context.Background(), path)
				if extra == 1 {
					require.ErrorIs(t, err, scanbudget.ErrExceeded)
					assert.Nil(t, components)
				} else {
					require.NoError(t, err)
					assert.Len(t, components, scanbudget.MaxComponents)
				}
			})
		}
	}
}

func TestMultiCollectorAggregateLimit(t *testing.T) {
	dir := t.TempDir()
	var data strings.Builder
	for i := range scanbudget.MaxComponents {
		fmt.Fprintf(&data, "require example.com/pkg%d v1.0.0\n", i)
	}
	require.NoError(t, os.WriteFile(filepath.Join(dir, "go.mod"), []byte(data.String()), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "requirements.txt"), []byte("pkg==1.0\n"), 0o600))
	components, err := (&MultiCollector{}).Collect(context.Background(), dir)
	require.ErrorIs(t, err, scanbudget.ErrExceeded)
	assert.Nil(t, components)
}
