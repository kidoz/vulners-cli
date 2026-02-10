package cmd

import (
	"context"
	"fmt"
	"os"

	"github.com/kidoz/vulners-cli/internal/cache"
	"github.com/kidoz/vulners-cli/internal/model"
	"github.com/kidoz/vulners-cli/internal/report"
)

// OfflineStatusCmd shows offline database status.
type OfflineStatusCmd struct{}

func (c *OfflineStatusCmd) Run(ctx context.Context, globals *CLI, store cache.Store) error {
	if err := validateNonScanFormat(globals.Output); err != nil {
		return err
	}
	metas, err := store.GetCollectionMeta(ctx)
	if err != nil {
		return fmt.Errorf("getting offline status: %w", err)
	}

	if len(metas) == 0 {
		fmt.Fprintln(os.Stderr, "No offline data synced. Run 'vulners offline sync' first.")
		return nil
	}

	reporter := report.New(model.OutputFormat(globals.Output))
	return reporter.Write(os.Stdout, metas)
}
