package host

import (
	"context"
	"errors"
	"runtime"
	"testing"
	"time"

	"github.com/kidoz/vulners-cli/internal/boundedio"
)

func TestLocalExecutor_OutputLimit(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix shell command")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	out, err := NewLocalExecutor().Execute(ctx, "exec head -c 1048577 /dev/zero >&2")
	if !errors.Is(err, boundedio.ErrOutputLimit) || out != "" {
		t.Fatalf("expected output limit without partial stdout, got %q, %v", out, err)
	}
}
