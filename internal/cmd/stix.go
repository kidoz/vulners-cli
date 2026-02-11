package cmd

import (
	"context"
	"fmt"
	"strings"
)

// StixCmd exports STIX bundles from Vulners.
type StixCmd struct {
	ID    string `arg:"" help:"Bulletin or CVE identifier"`
	ByCVE bool   `help:"Look up by CVE ID instead of bulletin ID"`
}

func (c *StixCmd) Run(ctx context.Context, globals *CLI, deps *Deps) error {
	if err := validateNonScanFormat(globals.Output); err != nil {
		return err
	}
	if globals.Offline {
		return fmt.Errorf("STIX export does not support offline mode")
	}
	if deps.Intel == nil {
		return fmt.Errorf("VULNERS_API_KEY is required for STIX export")
	}

	var result any
	var err error
	if c.ByCVE || strings.HasPrefix(c.ID, "CVE-") {
		result, err = deps.Intel.MakeSTIXBundleByCVE(ctx, c.ID)
	} else {
		result, err = deps.Intel.MakeSTIXBundleByID(ctx, c.ID)
	}
	if err != nil {
		return fmt.Errorf("STIX export failed: %w", err)
	}

	w, closer, werr := outputWriter(globals)
	if werr != nil {
		return werr
	}
	defer func() { _ = closer() }()

	return writeIntelOutput(w, globals, "stix", result, nil)
}
