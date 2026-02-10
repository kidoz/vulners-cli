package cmd

import (
	"context"
	"fmt"
	"os"

	"github.com/kidoz/vulners-cli/internal/model"
	"github.com/kidoz/vulners-cli/internal/report"
)

// WindowsAuditCmd audits Windows KB updates.
type WindowsAuditCmd struct {
	OS string   `help:"Windows OS version (e.g. 'Windows 10')" default:"Windows 10"`
	KB []string `help:"Installed KB identifiers" required:""`
}

func (c *WindowsAuditCmd) Run(ctx context.Context, globals *CLI, deps *Deps) error {
	if err := validateNonScanFormat(globals.Output); err != nil {
		return err
	}
	if globals.Offline {
		return fmt.Errorf("windows audit does not support offline mode")
	}
	if deps.Intel == nil {
		return fmt.Errorf("VULNERS_API_KEY is required for audit")
	}

	result, err := deps.Intel.KBAudit(ctx, c.OS, c.KB)
	if err != nil {
		return fmt.Errorf("windows audit failed: %w", err)
	}

	reporter := report.New(model.OutputFormat(globals.Output))
	return reporter.Write(os.Stdout, result)
}
