package cmd

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/kidoz/vulners-cli/internal/cache"
	"github.com/kidoz/vulners-cli/internal/inventory"
	"github.com/kidoz/vulners-cli/internal/matcher"
	"github.com/kidoz/vulners-cli/internal/model"
)

// ScanImageCmd scans a container image (requires syft for SBOM generation).
type ScanImageCmd struct {
	Image string `arg:"" help:"Image reference (e.g. alpine:3.18, ./image.tar)"`
}

func (c *ScanImageCmd) Run(ctx context.Context, globals *CLI, deps *Deps, store cache.Store, logger *slog.Logger) error {
	collector := &inventory.SyftCollector{}
	components, err := collector.Collect(ctx, c.Image)
	if err != nil {
		return fmt.Errorf("collecting image inventory: %w", err)
	}

	logger.Info("image scanned", "components", len(components), "image", c.Image)

	var findings []model.Finding
	if globals.Offline {
		findings, err = scanOfflineComponents(ctx, store, components, logger)
	} else {
		if deps.Intel == nil {
			return fmt.Errorf("VULNERS_API_KEY is required for online scanning")
		}
		m := matcher.NewMatcher(deps.Intel, logger)
		findings, err = m.Match(ctx, components)
	}
	if err != nil {
		return err
	}

	return finalizeScan(globals, c.Image, components, findings)
}
