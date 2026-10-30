package matcher

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/kidoz/vulners-cli/internal/affected"
	"github.com/kidoz/vulners-cli/internal/intel"
	"github.com/kidoz/vulners-cli/internal/model"
	"github.com/kidoz/vulners-cli/internal/scanbudget"
)

// searchLimit is the page size for product-scoped bulletin searches.
const searchLimit = 100

// Matcher resolves components to vulnerability findings.
type Matcher struct {
	intel  intel.Client
	logger *slog.Logger
}

// NewMatcher creates a new Matcher.
func NewMatcher(intelClient intel.Client, logger *slog.Logger) *Matcher {
	return &Matcher{intel: intelClient, logger: logger}
}

// Match queries the Vulners API for vulnerabilities affecting the given components.
func (m *Matcher) Match(ctx context.Context, components []model.Component) ([]model.Finding, error) {
	if err := scanbudget.CheckComponents(len(components)); err != nil {
		return nil, err
	}
	var findings []model.Finding
	requests := 0

	for _, comp := range components {
		comp = NormalizeComponent(comp)
		query := buildQuery(comp)
		if query == "" {
			continue
		}

		m.logger.Debug("querying vulners", "component", comp.Name, "version", comp.Version)

		matched, err := m.matchComponent(ctx, comp, query, &requests)
		if err != nil {
			return nil, err
		}
		findings = append(findings, matched...)
	}

	return findings, nil
}

// matchComponent pages through product-scoped candidates; range boundaries can
// differ from the installed version, so the query must not filter by that version.
func (m *Matcher) matchComponent(ctx context.Context, comp model.Component, query string, requests *int) ([]model.Finding, error) {
	var findings []model.Finding
	for offset := 0; ; {
		if err := ctx.Err(); err != nil {
			return nil, fmt.Errorf("search aborted: %w", err)
		}
		if *requests >= scanbudget.MaxSearchRequests {
			return nil, fmt.Errorf("%w: maximum %d API search requests", scanbudget.ErrExceeded, scanbudget.MaxSearchRequests)
		}
		*requests += 1
		result, err := m.intel.Search(ctx, query, searchLimit, offset)
		if err != nil {
			if ctx.Err() != nil {
				return nil, fmt.Errorf("search aborted: %w", ctx.Err())
			}
			return nil, fmt.Errorf("searching %s@%s: %w", comp.Name, comp.Version, err)
		}
		for _, b := range result.Bulletins {
			matches, matchErr := affected.Matches(&b, comp.Name, comp.Version, comp.CPE)
			if matchErr != nil {
				return nil, matchErr
			}
			if matches {
				findings = append(findings, BulletinToFinding(&b, comp.Name+"@"+comp.Version))
			}
		}
		count := len(result.Bulletins)
		offset += count
		if count == 0 || (result.Total > 0 && offset >= result.Total) || (result.Total == 0 && count < searchLimit) {
			break
		}
	}
	return findings, nil
}

func buildQuery(comp model.Component) string {
	if comp.CPE != "" {
		return fmt.Sprintf("affectedSoftware.cpe:%q", comp.CPE)
	}
	if comp.Name != "" && comp.Version != "" {
		return fmt.Sprintf("affectedSoftware.name:%q", comp.Name)
	}
	return ""
}
