package cmd

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/kidoz/vulners-cli/internal/cache"
)

// OfflinePurgeCmd clears the offline database.
type OfflinePurgeCmd struct{}

func (c *OfflinePurgeCmd) Run(ctx context.Context, store cache.Store, logger *slog.Logger) error {
	if err := store.Purge(ctx); err != nil {
		return fmt.Errorf("purging offline database: %w", err)
	}
	logger.Info("offline database purged")
	return nil
}
