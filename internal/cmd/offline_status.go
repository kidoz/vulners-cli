package cmd

import (
	"context"
	"fmt"
	"os"

	"github.com/kidoz/vulners-cli/internal/cache"
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

	w, closer, werr := outputWriter(globals)
	if werr != nil {
		return werr
	}
	defer func() { _ = closer() }()

	return writeIntelOutput(w, globals, "offline status", metas, nil)
}
