package cmd

import (
	"context"
	"fmt"
	"os"

	"github.com/kidoz/vulners-cli/internal/cache"
	"github.com/kidoz/vulners-cli/internal/model"
	"github.com/kidoz/vulners-cli/internal/report"
)

// SearchCmd searches the Vulners database.
type SearchCmd struct {
	Query    string `arg:"" help:"Lucene search query"`
	Limit    int    `help:"Maximum results to return" default:"10"`
	Offset   int    `help:"Result offset for pagination" default:"0"`
	Exploits bool   `help:"Search exploits only"`
}

func (c *SearchCmd) Run(ctx context.Context, globals *CLI, deps *Deps, store cache.Store) error {
	if err := validateNonScanFormat(globals.Output); err != nil {
		return err
	}
	reporter := report.New(model.OutputFormat(globals.Output))

	if globals.Offline {
		bulletins, _, err := store.SearchBulletins(ctx, c.Query, c.Limit, c.Offset)
		if err != nil {
			return fmt.Errorf("offline search failed: %w", err)
		}
		return reporter.Write(os.Stdout, bulletins)
	}

	if deps.Intel == nil {
		return fmt.Errorf("VULNERS_API_KEY is required for search")
	}

	var result any
	var err error
	if c.Exploits {
		result, err = deps.Intel.SearchExploits(ctx, c.Query, c.Limit, c.Offset)
	} else {
		result, err = deps.Intel.Search(ctx, c.Query, c.Limit, c.Offset)
	}
	if err != nil {
		return fmt.Errorf("search failed: %w", err)
	}

	return reporter.Write(os.Stdout, result)
}
