package main

import (
	"log/slog"
	"testing"

	"github.com/kidoz/vulners-cli/internal/config"

	icmd "github.com/kidoz/vulners-cli/internal/cmd"
)

func TestKongExitCode(t *testing.T) {
	if got := kongExitCode(0); got != int(icmd.ExitOK) {
		t.Fatalf("kongExitCode(0) = %d, want 0", got)
	}
	for _, code := range []int{1, 80} {
		if got := kongExitCode(code); got != int(icmd.ExitUsageError) {
			t.Fatalf("kongExitCode(%d) = %d, want 2", code, got)
		}
	}
}

func TestProvideDeps_AIScoreConfig(t *testing.T) {
	deps, err := provideDeps(&config.Config{EnableAIScore: true}, slog.Default())
	if err != nil {
		t.Fatal(err)
	}
	if !deps.EnableAIScore {
		t.Fatal("AI score configuration was lost")
	}
}
