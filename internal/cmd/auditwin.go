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

// WinFullAuditCmd audits Windows using the WinAudit API (KBs + software).
type WinFullAuditCmd struct {
	OS       string   `help:"Windows version (e.g. 'Windows 10')" required:""`
	Version  string   `help:"OS build version" required:""`
	KB       []string `help:"Installed KB numbers"`
	Software []string `help:"Installed software in 'name version' format"`
}

func (c *WinFullAuditCmd) Run(ctx context.Context, globals *CLI, deps *Deps) error {
	if err := validateNonScanFormat(globals.Output); err != nil {
		return err
	}
	if globals.Offline {
		return fmt.Errorf("windows audit does not support offline mode")
	}
	if deps.Intel == nil {
		return fmt.Errorf("VULNERS_API_KEY is required for Windows audit")
	}

	var items []vulners.WinAuditItem
	for _, sw := range c.Software {
		parts := strings.SplitN(sw, " ", 2)
		item := vulners.WinAuditItem{Software: parts[0]}
		if len(parts) > 1 {
			item.Version = parts[1]
		}
		items = append(items, item)
	}

	result, err := deps.Intel.WinAudit(ctx, c.OS, c.Version, c.KB, items)
	if err != nil {
		return fmt.Errorf("windows audit failed: %w", err)
	}

	reporter := report.New(model.OutputFormat(globals.Output))
	return reporter.Write(os.Stdout, result)
}
