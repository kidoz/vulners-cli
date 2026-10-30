package cmd

import (
	"github.com/kidoz/vulners-cli/internal/intel"
)

// Deps holds shared dependencies injected into commands.
type Deps struct {
	EnableAIScore bool
	Intel         intel.Client
	VScanner      intel.VScannerClient
}
