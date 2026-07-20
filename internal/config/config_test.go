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

func TestLoad_BoolEnvAcceptedForms(t *testing.T) {
	// strconv.ParseBool accepts these forms. Each must be honored faithfully
	// (especially "false" — a common footgun where env coercion surprises users).
	for _, val := range []string{"1", "t", "T", "TRUE", "true", "True"} {
		t.Run("offline="+val, func(t *testing.T) {
			t.Setenv("VULNERS_OFFLINE", val)
			t.Setenv("VULNERS_CONFIG", filepath.Join(t.TempDir(), "nonexistent.yaml"))
			cfg, err := Load()
			require.NoError(t, err)
			assert.True(t, cfg.Offline, "value %q should parse as true", val)
		})
	}
	for _, val := range []string{"0", "f", "F", "FALSE", "false", "False"} {
		t.Run("offline="+val, func(t *testing.T) {
			t.Setenv("VULNERS_OFFLINE", val)
			t.Setenv("VULNERS_CONFIG", filepath.Join(t.TempDir(), "nonexistent.yaml"))
			cfg, err := Load()
			require.NoError(t, err)
			assert.False(t, cfg.Offline, "value %q should parse as false", val)
		})
	}
}

func TestLoad_BoolEnvInvalidRejected(t *testing.T) {
	// Values like "yes"/"no"/"off" are NOT valid booleans per strconv.ParseBool
	// and must produce an error rather than a silent surprise.
	for _, val := range []string{"yes", "no", "off", "on", "2", "maybe"} {
		t.Run("offline="+val, func(t *testing.T) {
			t.Setenv("VULNERS_OFFLINE", val)
			t.Setenv("VULNERS_CONFIG", filepath.Join(t.TempDir(), "nonexistent.yaml"))
			_, err := Load()
			require.Error(t, err, "value %q should be rejected", val)
			assert.Contains(t, err.Error(), "must be a boolean")
		})
	}
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

func TestLoad_MaxResponseSizeEnv(t *testing.T) {
	t.Setenv("VULNERS_CONFIG", filepath.Join(t.TempDir(), "nonexistent.yaml"))

	t.Run("valid integer is parsed", func(t *testing.T) {
		t.Setenv("VULNERS_MAX_RESPONSE_SIZE", "536870912") // 512 MiB
		cfg, err := Load()
		require.NoError(t, err)
		assert.Equal(t, int64(536870912), cfg.MaxResponseSize)
	})

	t.Run("empty/unset keeps zero default", func(t *testing.T) {
		t.Setenv("VULNERS_MAX_RESPONSE_SIZE", "")
		cfg, err := Load()
		require.NoError(t, err)
		assert.Equal(t, int64(0), cfg.MaxResponseSize, "empty env should not override default")
	})

	t.Run("invalid value is rejected", func(t *testing.T) {
		t.Setenv("VULNERS_MAX_RESPONSE_SIZE", "512MB")
		_, err := Load()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "must be an integer number of bytes")
	})
}
