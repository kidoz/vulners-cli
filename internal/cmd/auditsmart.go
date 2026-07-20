package cmd

import (
	"context"
	"fmt"
)

// SmartAuditCmd resolves free-form software descriptions and audits the matches.
type SmartAuditCmd struct {
	Software []string `help:"Software description to resolve and audit (repeatable)" required:""`
	Catalog  string   `help:"Vulnerability catalog to use" enum:"official,extended" default:"official"`
}

// Run executes the 'audit smart' command.
func (c *SmartAuditCmd) Run(ctx context.Context, globals *CLI, deps *Deps) error {
	if err := validateNonScanFormat(globals.Output); err != nil {
		return err
	}
	if globals.Offline {
		return fmt.Errorf("smart audit does not support offline mode")
	}
	if deps.Intel == nil {
		return fmt.Errorf("VULNERS_API_KEY is required for audit")
	}
	if len(c.Software) == 0 {
		return fmt.Errorf("no software descriptions provided for audit")
	}

	result, err := deps.Intel.SmartAudit(ctx, c.Software, c.Catalog)
	if err != nil {
		return fmt.Errorf("smart audit failed: %w", err)
	}

	w, closer, werr := outputWriter(globals)
	if werr != nil {
		return werr
	}
	defer func() { _ = closer() }()

	return writeIntelOutput(w, globals, "audit smart", result, nil)
}
