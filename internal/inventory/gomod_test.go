package inventory

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGoModCollector_Collect(t *testing.T) {
	// Copy fixture to temp dir as go.mod.
	fixture, err := os.ReadFile("../../testdata/go.mod.fixture")
	require.NoError(t, err)

	dir := t.TempDir()
	err = os.WriteFile(filepath.Join(dir, "go.mod"), fixture, 0o600)
	require.NoError(t, err)

	collector := &GoModCollector{}
	components, err := collector.Collect(context.Background(), dir)
	require.NoError(t, err)

	assert.Len(t, components, 3)

	names := make([]string, len(components))
	for i, c := range components {
		names[i] = c.Name
	}
	assert.Contains(t, names, "github.com/gorilla/mux")
	assert.Contains(t, names, "golang.org/x/crypto")
	assert.Contains(t, names, "github.com/sirupsen/logrus")
}

func TestGoModCollector_PURLFormat(t *testing.T) {
	fixture, err := os.ReadFile("../../testdata/go.mod.fixture")
	require.NoError(t, err)

	dir := t.TempDir()
	err = os.WriteFile(filepath.Join(dir, "go.mod"), fixture, 0o600)
	require.NoError(t, err)

	collector := &GoModCollector{}
	components, err := collector.Collect(context.Background(), dir)
	require.NoError(t, err)

	for _, c := range components {
		if c.Name == "github.com/gorilla/mux" {
			assert.Equal(t, "pkg:golang/github.com/gorilla/mux@v1.8.0", c.PURL)
			return
		}
	}
	t.Fatal("github.com/gorilla/mux not found")
}

func TestGoModCollector_PURL(t *testing.T) {
	fixture, err := os.ReadFile("../../testdata/go.mod.fixture")
	require.NoError(t, err)

	dir := t.TempDir()
	err = os.WriteFile(filepath.Join(dir, "go.mod"), fixture, 0o600)
	require.NoError(t, err)

	collector := &GoModCollector{}
	components, err := collector.Collect(context.Background(), dir)
	require.NoError(t, err)

	for _, c := range components {
		assert.NotEmpty(t, c.PURL, "PURL should be set for %s", c.Name)
		assert.Contains(t, c.PURL, "pkg:golang/")
	}
}

func TestGoModCollector_NoGoMod(t *testing.T) {
	collector := &GoModCollector{}
	_, err := collector.Collect(context.Background(), t.TempDir())
	assert.Error(t, err)
}
