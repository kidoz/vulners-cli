package cmd

import (
	"context"
	"fmt"

	"github.com/kidoz/vulners-cli/internal/cache"
)

// CPECmd searches by CPE.
type CPECmd struct {
	Product string `arg:"" help:"Product name to search"`
	Vendor  string `help:"Vendor name" default:""`
	Limit   int    `help:"Maximum results to return" default:"10"`
}

func (c *CPECmd) Run(ctx context.Context, globals *CLI, deps *Deps, store cache.Store) error {
	if err := validateNonScanFormat(globals.Output); err != nil {
		return err
	}

	w, closer, err := outputWriter(globals)
	if err != nil {
		return err
	}
	defer func() { _ = closer() }()

	if globals.Offline {
		bulletins, total, err := store.SearchBulletins(ctx, c.Product, c.Limit, 0)
		if err != nil {
			return fmt.Errorf("offline CPE search failed: %w", err)
		}
		return writeIntelOutput(w, globals, "cpe", bulletins, map[string]any{"total": total})
	}

	if deps.Intel == nil {
		return fmt.Errorf("VULNERS_API_KEY is required for CPE search")
	}

	vendor := c.Vendor
	if vendor == "" {
		vendor = c.Product
	}

	result, err := deps.Intel.SearchCPE(ctx, c.Product, vendor, c.Limit)
	if err != nil {
		return fmt.Errorf("CPE search failed: %w", err)
	}

	return writeIntelOutput(w, globals, "cpe", result, nil)
}
