package cmd

import (
	"context"
	"fmt"
	"os"
	"strings"

	vulners "github.com/kidoz/go-vulners"
	"github.com/kidoz/vulners-cli/internal/model"
	"github.com/kidoz/vulners-cli/internal/report"
)

// HostAuditCmd audits host packages using the v4 Host audit API.
type HostAuditCmd struct {
	OS       string   `help:"Operating system name (e.g. ubuntu, centos)" required:""`
	Version  string   `help:"OS version (e.g. 22.04, 8)" required:""`
	Packages []string `help:"Packages in 'name version' format" required:""`
}

func (c *HostAuditCmd) Run(ctx context.Context, globals *CLI, deps *Deps) error {
	if err := validateNonScanFormat(globals.Output); err != nil {
		return err
	}
	if globals.Offline {
		return fmt.Errorf("host audit does not support offline mode")
	}
	if deps.Intel == nil {
		return fmt.Errorf("VULNERS_API_KEY is required for host audit")
	}

	var items []vulners.AuditItem
	for _, pkg := range c.Packages {
		parts := strings.SplitN(pkg, " ", 2)
		item := vulners.AuditItem{Software: parts[0]}
		if len(parts) > 1 {
			item.Version = parts[1]
		}
		items = append(items, item)
	}

	result, err := deps.Intel.HostAudit(ctx, c.OS, c.Version, items)
	if err != nil {
		return fmt.Errorf("host audit failed: %w", err)
	}

	reporter := report.New(model.OutputFormat(globals.Output))
	return reporter.Write(os.Stdout, result)
}
