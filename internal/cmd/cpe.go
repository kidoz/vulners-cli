package cmd

import (
	"context"
	"fmt"
	"os"

	"github.com/kidoz/vulners-cli/internal/cache"
	"github.com/kidoz/vulners-cli/internal/model"
	"github.com/kidoz/vulners-cli/internal/report"
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
	reporter := report.New(model.OutputFormat(globals.Output))

	if globals.Offline {
		bulletins, _, err := store.SearchBulletins(ctx, c.Product, c.Limit, 0)
		if err != nil {
			return fmt.Errorf("offline CPE search failed: %w", err)
		}
		return reporter.Write(os.Stdout, bulletins)
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

	return reporter.Write(os.Stdout, result)
}
