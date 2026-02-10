package inventory

import (
	"context"

	"github.com/kidoz/vulners-cli/internal/model"
)

// Collector collects software components from a target.
type Collector interface {
	Collect(ctx context.Context, target string) ([]model.Component, error)
}
