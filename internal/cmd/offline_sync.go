package cmd

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"time"

	vulners "github.com/kidoz/go-vulners"

	"github.com/kidoz/vulners-cli/internal/cache"
)

// OfflineSyncCmd syncs vulnerability data for offline use.
type OfflineSyncCmd struct {
	Collections []string `help:"Collections to sync (e.g. cve,exploit,debian)" default:"cve"`
	Full        bool     `help:"Force full sync even if recent data exists"`
}

// deltaThreshold is the maximum age of a sync before a full sync is required.
const deltaThreshold = 25 * time.Hour

func (c *OfflineSyncCmd) Run(ctx context.Context, globals *CLI, deps *Deps, store cache.Store, logger *slog.Logger) error {
	if deps.Intel == nil {
		return fmt.Errorf("VULNERS_API_KEY is required for offline sync")
	}

	// Expand comma-separated values so "--collections cve,exploit" works.
	var collections []string
	for _, raw := range c.Collections {
		for _, part := range strings.Split(raw, ",") {
			if s := strings.TrimSpace(part); s != "" {
				collections = append(collections, s)
			}
		}
	}

	for _, coll := range collections {
		collType := vulners.CollectionType(coll)

		var bulletins []vulners.Bulletin
		var err error

		lastSync, syncErr := store.GetLastSyncTime(ctx, coll)
		useDelta := !c.Full && syncErr == nil && !lastSync.IsZero() && time.Since(lastSync) < deltaThreshold

		if useDelta {
			logger.Info("incremental sync", "collection", coll, "since", lastSync.Format(time.RFC3339))
			bulletins, err = deps.Intel.FetchCollectionUpdate(ctx, collType, lastSync)
			if err != nil {
				// Don't retry if the context was cancelled (e.g. SIGINT).
				if ctx.Err() != nil {
					return fmt.Errorf("sync cancelled: %w", ctx.Err())
				}
				logger.Warn("delta sync failed, falling back to full sync", "collection", coll, "error", err)
				bulletins, err = deps.Intel.FetchCollection(ctx, collType)
			}
		} else {
			logger.Info("full sync", "collection", coll)
			bulletins, err = deps.Intel.FetchCollection(ctx, collType)
		}
		if err != nil {
			return fmt.Errorf("fetching collection %s: %w", coll, err)
		}

		logger.Info("storing bulletins", "collection", coll, "count", len(bulletins))
		if err := store.PutBulletins(ctx, coll, bulletins); err != nil {
			return fmt.Errorf("storing collection %s: %w", coll, err)
		}
	}

	logger.Info("sync complete")
	return nil
}
