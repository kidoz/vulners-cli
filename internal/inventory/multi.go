package inventory

import (
	"cmp"
	"context"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"slices"

	"github.com/kidoz/vulners-cli/internal/model"
)

// manifestCollectors maps manifest filenames to their respective collectors.
var manifestCollectors = map[string]Collector{
	"go.mod":            &GoModCollector{},
	"package-lock.json": &NPMCollector{},
	"requirements.txt":  &PipCollector{},
}

// MultiCollector discovers package manifests in a directory and dispatches to
// the appropriate collector for each one.
type MultiCollector struct{}

func (c *MultiCollector) Collect(ctx context.Context, dir string) ([]model.Component, error) {
	var all []model.Component

	// Sort manifest keys for deterministic iteration order.
	keys := make([]string, 0, len(manifestCollectors))
	for k := range manifestCollectors {
		keys = append(keys, k)
	}
	slices.Sort(keys)

	for _, filename := range keys {
		collector := manifestCollectors[filename]
		target := filepath.Join(dir, filename)
		components, err := collector.Collect(ctx, target)
		if err != nil {
			if !errors.Is(err, os.ErrNotExist) {
				slog.Warn("failed to collect from manifest", "file", target, "error", err)
			}
			continue
		}
		all = append(all, components...)
	}

	// Sort for deterministic output across runs.
	slices.SortFunc(all, func(a, b model.Component) int {
		if c := cmp.Compare(a.Type, b.Type); c != 0 {
			return c
		}
		if c := cmp.Compare(a.Name, b.Name); c != 0 {
			return c
		}
		return cmp.Compare(a.Version, b.Version)
	})

	return all, nil
}
