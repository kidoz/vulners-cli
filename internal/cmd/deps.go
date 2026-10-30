package cmd

import (
	"context"

	"github.com/kidoz/vulners-cli/internal/host"
	"github.com/kidoz/vulners-cli/internal/intel"
)

// Deps holds shared dependencies injected into commands.
type Deps struct {
	HostExecutorFactory func(context.Context, string, host.ExecutorOptions) (host.Executor, error)
	EnableAIScore       bool
	Intel               intel.Client
}
