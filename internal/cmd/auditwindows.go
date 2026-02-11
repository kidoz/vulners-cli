package cmd

import (
	"context"
	"fmt"
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

	w, closer, werr := outputWriter(globals)
	if werr != nil {
		return werr
	}
	defer func() { _ = closer() }()

	return writeIntelOutput(w, globals, "audit windows", result, nil)
}
