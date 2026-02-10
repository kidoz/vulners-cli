package cmd

import (
	"context"
	"fmt"
	"log/slog"
	"path/filepath"

	"github.com/kidoz/vulners-cli/internal/cache"
	"github.com/kidoz/vulners-cli/internal/inventory"
	"github.com/kidoz/vulners-cli/internal/matcher"
	"github.com/kidoz/vulners-cli/internal/model"
)

// ScanDirCmd scans a directory for package manifests and finds vulnerabilities.
type ScanDirCmd struct {
	Path string `arg:"" help:"Directory path to scan" default:"."`
}

func (c *ScanDirCmd) Run(ctx context.Context, globals *CLI, deps *Deps, store cache.Store, logger *slog.Logger) error {
	absPath, err := filepath.Abs(c.Path)
	if err != nil {
		return fmt.Errorf("resolving path: %w", err)
	}

	collector := &inventory.MultiCollector{}
	components, err := collector.Collect(ctx, absPath)
	if err != nil {
		return fmt.Errorf("collecting inventory: %w", err)
	}

	if len(components) == 0 {
		logger.Info("no package manifests found", "path", absPath)
	} else {
		logger.Info("inventory collected", "components", len(components), "path", absPath)
	}

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

	return finalizeScan(globals, absPath, components, findings)
}
