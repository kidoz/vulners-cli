package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoad_Defaults(t *testing.T) {
	t.Setenv("VULNERS_API_KEY", "")
	t.Setenv("VULNERS_CONFIG", filepath.Join(t.TempDir(), "nonexistent.yaml"))

	cfg, err := Load()
	require.NoError(t, err)

	assert.Empty(t, cfg.APIKey)
	assert.Contains(t, cfg.DBPath, "vulners.db")
	assert.False(t, cfg.Verbose)
	assert.False(t, cfg.Quiet)
	assert.False(t, cfg.Offline)
}

func TestLoad_EnvOverrides(t *testing.T) {
	t.Setenv("VULNERS_API_KEY", "test-key-123")
	t.Setenv("VULNERS_CONFIG", filepath.Join(t.TempDir(), "nonexistent.yaml"))

	cfg, err := Load()
	require.NoError(t, err)

	assert.Equal(t, "test-key-123", cfg.APIKey)
}

func TestLoad_DBPathEnv(t *testing.T) {
	t.Setenv("VULNERS_DB_PATH", "/tmp/test.db")
	t.Setenv("VULNERS_CONFIG", filepath.Join(t.TempDir(), "nonexistent.yaml"))

	cfg, err := Load()
	require.NoError(t, err)

	assert.Equal(t, "/tmp/test.db", cfg.DBPath)
}

func TestLoad_OfflineEnv(t *testing.T) {
	t.Setenv("VULNERS_OFFLINE", "true")
	t.Setenv("VULNERS_CONFIG", filepath.Join(t.TempDir(), "nonexistent.yaml"))

	cfg, err := Load()
	require.NoError(t, err)

	assert.True(t, cfg.Offline)
}

func TestLoad_YAMLFile(t *testing.T) {
	dir := t.TempDir()
	cfgFile := filepath.Join(dir, "config.yaml")
	err := os.WriteFile(cfgFile, []byte("api_key: yaml-key-456\nverbose: true\n"), 0o600)
	require.NoError(t, err)

	t.Setenv("VULNERS_CONFIG", cfgFile)
	// Set API key to empty so env provider doesn't override the YAML value.
	t.Setenv("VULNERS_API_KEY", "")

	cfg, err := Load()
	require.NoError(t, err)

	assert.Equal(t, "yaml-key-456", cfg.APIKey)
	assert.True(t, cfg.Verbose)
}

func TestLoad_EnvOverridesYAML(t *testing.T) {
	dir := t.TempDir()
	cfgFile := filepath.Join(dir, "config.yaml")
	err := os.WriteFile(cfgFile, []byte("api_key: yaml-key\ndb_path: /yaml/path.db\n"), 0o600)
	require.NoError(t, err)

	t.Setenv("VULNERS_CONFIG", cfgFile)
	t.Setenv("VULNERS_API_KEY", "env-key")

	cfg, err := Load()
	require.NoError(t, err)

	assert.Equal(t, "env-key", cfg.APIKey, "env should override YAML")
	assert.Equal(t, "/yaml/path.db", cfg.DBPath, "YAML should override default")
}
