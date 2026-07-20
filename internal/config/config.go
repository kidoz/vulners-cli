package config

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"

	"github.com/knadh/koanf/parsers/yaml"
	"github.com/knadh/koanf/providers/confmap"
	"github.com/knadh/koanf/providers/env"
	"github.com/knadh/koanf/providers/file"
	"github.com/knadh/koanf/v2"
)

// Config holds the application configuration.
type Config struct {
	APIKey          string `koanf:"api_key"` //nolint:gosec
	DBPath          string `koanf:"db_path"`
	Verbose         bool   `koanf:"verbose"`
	Quiet           bool   `koanf:"quiet"`
	Offline         bool   `koanf:"offline"`
	EnableAIScore   bool   `koanf:"enable_ai_score"`
	MaxResponseSize int64  `koanf:"max_response_size"`
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

	// Load YAML config file (optional — missing file is not an error,
	// but a malformed file that exists is).
	cfgPath := configFilePath()
	if _, err := os.Stat(cfgPath); err == nil {
		if err := k.Load(file.Provider(cfgPath), yaml.Parser()); err != nil {
			return nil, fmt.Errorf("parsing config file %s: %w", cfgPath, err)
		}
	}

	// Validate typed env vars explicitly so invalid values fail loudly instead
	// of being silently coerced by Koanf's string conversion (which can surprise
	// users — e.g. "false" not reliably producing false).
	if err := validateEnvVars(); err != nil {
		return nil, err
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
		case "VULNERS_MAX_RESPONSE_SIZE":
			// Parsed to int64 so Koanf doesn't coerce strings. Pre-validated
			// below; a non-positive value means "use the go-vulners default".
			n, _ := strconv.ParseInt(value, 10, 64)
			return "max_response_size", n
		case "VULNERS_VERBOSE", "VULNERS_QUIET", "VULNERS_OFFLINE", "VULNERS_ENABLE_AI_SCORE":
			// Pre-validated above; parse to bool so Koanf doesn't coerce strings.
			b, _ := strconv.ParseBool(value)
			return envKeyToKoanf(key), b
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

// validateEnvVars checks typed VULNERS_* env vars so invalid values fail
// loudly instead of being silently coerced.
//
// Booleans use strconv.ParseBool semantics (1, t, T, TRUE, true, True, 0, f,
// F, FALSE, false, False); anything else (yes, no, off, on, 2...) is rejected.
// VULNERS_MAX_RESPONSE_SIZE must be an integer number of bytes (non-positive
// means "use the go-vulners default").
func validateEnvVars() error {
	boolKeys := []string{"VULNERS_VERBOSE", "VULNERS_QUIET", "VULNERS_OFFLINE", "VULNERS_ENABLE_AI_SCORE"}
	for _, key := range boolKeys {
		if v, ok := os.LookupEnv(key); ok && v != "" {
			if _, err := strconv.ParseBool(v); err != nil {
				return fmt.Errorf("env %s=%q must be a boolean (true/false, 1/0)", key, v)
			}
		}
	}
	if v, ok := os.LookupEnv("VULNERS_MAX_RESPONSE_SIZE"); ok && v != "" {
		if _, err := strconv.ParseInt(v, 10, 64); err != nil {
			return fmt.Errorf("env VULNERS_MAX_RESPONSE_SIZE=%q must be an integer number of bytes", v)
		}
	}
	return nil
}

// envKeyToKoanf maps a VULNERS_ env var name to its koanf config key.
func envKeyToKoanf(key string) string {
	switch key {
	case "VULNERS_VERBOSE":
		return "verbose"
	case "VULNERS_QUIET":
		return "quiet"
	case "VULNERS_OFFLINE":
		return "offline"
	case "VULNERS_ENABLE_AI_SCORE":
		return "enable_ai_score"
	default:
		return ""
	}
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
