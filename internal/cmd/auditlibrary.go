package cmd

import (
	"context"
	"fmt"
)

// LibraryAuditCmd audits libraries identified by Package URLs (PURLs).
type LibraryAuditCmd struct {
	Purl []string `arg:"" help:"Package URL(s) to audit (e.g. pkg:npm/lodash@4.17.20)" required:""`
}

// Run executes the 'audit library' command.
func (c *LibraryAuditCmd) Run(ctx context.Context, globals *CLI, deps *Deps) error {
	if err := validateNonScanFormat(globals.Output); err != nil {
		return err
	}
	if globals.Offline {
		return fmt.Errorf("library audit does not support offline mode")
	}
	if deps.Intel == nil {
		return fmt.Errorf("VULNERS_API_KEY is required for audit")
	}
	if len(c.Purl) == 0 {
		return fmt.Errorf("no package URLs provided for audit")
	}

	result, err := deps.Intel.LibraryAudit(ctx, c.Purl)
	if err != nil {
		return fmt.Errorf("library audit failed: %w", err)
	}

	w, closer, werr := outputWriter(globals)
	if werr != nil {
		return werr
	}
	defer func() { _ = closer() }()

	return writeIntelOutput(w, globals, "audit library", result, nil)
}
