package cmd

import (
	"io"
	"log/slog"
	"os"
	"testing"

	"github.com/kidoz/vulners-cli/internal/cache"
	"github.com/kidoz/vulners-cli/internal/intel"
)

// jsonCLI returns a CLI with JSON output (default).
func jsonCLI() *CLI {
	return &CLI{Output: "json"}
}

// tableCLI returns a CLI with table output.
func tableCLI() *CLI {
	return &CLI{Output: "table"}
}

// sarifCLI returns a CLI with SARIF output (scan-only format).
func sarifCLI() *CLI {
	return &CLI{Output: "sarif"}
}

// offlineCLI returns a CLI with offline mode and JSON output.
func offlineCLI() *CLI {
	return &CLI{Output: "json", Offline: true}
}

// testDeps returns Deps wired to the given intel.Client.
func testDeps(client intel.Client) *Deps {
	return &Deps{Intel: client}
}

// nilDeps returns Deps with a nil intel client (simulates missing API key).
func nilDeps() *Deps {
	return &Deps{Intel: nil}
}

// nopStore returns a NopStore for tests that don't exercise offline paths.
func nopStore() cache.Store {
	return cache.NewNopStore()
}

// discardLogger returns a logger that writes nowhere.
func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// captureStdout captures os.Stdout output during fn execution.
func captureStdout(t *testing.T, fn func()) []byte {
	t.Helper()
	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	os.Stdout = w
	defer func() {
		os.Stdout = old
	}()
	fn()
	_ = w.Close()
	out, _ := io.ReadAll(r)
	return out
}
