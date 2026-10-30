package main

import (
	"testing"

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
