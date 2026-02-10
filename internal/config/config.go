package config

import (
	"log/slog"
	"os"
	"path/filepath"

	"github.com/knadh/koanf/parsers/yaml"
	"github.com/knadh/koanf/providers/confmap"
	"github.com/knadh/koanf/providers/env"
	"github.com/knadh/koanf/providers/file"
	"github.com/knadh/koanf/v2"
)

// Config holds the application configuration.
type Config struct {
	APIKey        string `koanf:"api_key"`
	DBPath        string `koanf:"db_path"`
	Verbose       bool   `koanf:"verbose"`
	Quiet         bool   `koanf:"quiet"`
	Offline       bool   `koanf:"offline"`
	EnableAIScore bool   `koanf:"enable_ai_score"`
}

// Load reads configuration from defaults, config file, and environment variables.
// Precedence: defaults → YAML file → env vars.
func Load() (*Config, error) {
	k := koanf.New(".")

	defaults := map[string]any{
		"db_path": defaultDBPath(),
	}
	if err := k.Load(confmap.Provider(defaults, "."), nil); err != nil {
		return nil, err
	}

	// Load YAML config file (optional — missing file is not an error).
	cfgPath := configFilePath()
	if _, err := os.Stat(cfgPath); err == nil {
		if err := k.Load(file.Provider(cfgPath), yaml.Parser()); err != nil {
			slog.Warn("failed to load config file", "path", cfgPath, "error", err)
		}
	}

	if err := k.Load(env.ProviderWithValue("VULNERS_", ".", func(key, value string) (string, interface{}) {
		if value == "" {
			return "", nil // skip empty env vars so they don't override file/defaults
		}
		switch key {
		case "VULNERS_API_KEY":
			return "api_key", value
		case "VULNERS_DB_PATH":
			return "db_path", value
		case "VULNERS_VERBOSE":
			return "verbose", value
		case "VULNERS_QUIET":
			return "quiet", value
		case "VULNERS_OFFLINE":
			return "offline", value
		case "VULNERS_ENABLE_AI_SCORE":
			return "enable_ai_score", value
		default:
			return "", nil
		}
	}), nil); err != nil {
		return nil, err
	}

	var cfg Config
	if err := k.Unmarshal("", &cfg); err != nil {
		return nil, err
	}

	return &cfg, nil
}

// configFilePath returns the YAML config file path.
// VULNERS_CONFIG env overrides the default ~/.vulners/config.yaml.
func configFilePath() string {
	if p := os.Getenv("VULNERS_CONFIG"); p != "" {
		return p
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".vulners", "config.yaml")
}

func defaultDBPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		slog.Warn("cannot determine home directory, using temp path for database", "error", err, "path", filepath.Join(os.TempDir(), "vulners.db"))
		return filepath.Join(os.TempDir(), "vulners.db")
	}
	return filepath.Join(home, ".vulners", "vulners.db")
}
