package matcher

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/kidoz/vulners-cli/internal/intel"
	"github.com/kidoz/vulners-cli/internal/model"
)

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
	var findings []model.Finding
	var skipped int

	for _, comp := range components {
		comp = NormalizeComponent(comp)
		query := buildQuery(comp)
		if query == "" {
			continue
		}

		m.logger.Debug("querying vulners", "component", comp.Name, "version", comp.Version)

		result, err := m.intel.Search(ctx, query, 20, 0)
		if err != nil {
			// Propagate context errors — they signal the caller cancelled or timed out.
			if ctx.Err() != nil {
				return nil, fmt.Errorf("search aborted: %w", ctx.Err())
			}
			m.logger.Warn("search failed for component", "name", comp.Name, "error", err)
			skipped++
			continue
		}

		for _, b := range result.Bulletins {
			severity := "unknown"
			var cvss float64
			if b.CVSS != nil {
				cvss = b.CVSS.Score
				severity = model.ScoreSeverity(cvss)
			}

			f := model.Finding{
				VulnID:       b.ID,
				Aliases:      b.CVEList,
				Severity:     severity,
				CVSS:         cvss,
				HasExploit:   b.Type == "exploit",
				ComponentRef: comp.Name + "@" + comp.Version,
			}

			if b.Href != "" {
				f.References = []string{b.Href}
			}
			if len(b.Epss) > 0 && b.Epss[0].Epss > 0 {
				v := b.Epss[0].Epss
				f.EPSS = &v
			}
			if b.AI != nil {
				score := b.AI.Score
				f.AIScore = &score
			}

			findings = append(findings, f)
		}
	}

	if skipped > 0 {
		m.logger.Warn("components skipped due to search errors",
			"skipped", skipped, "total", len(components))
	}

	return findings, nil
}

func buildQuery(comp model.Component) string {
	if comp.CPE != "" {
		return fmt.Sprintf("affectedSoftware.cpe:%s", comp.CPE)
	}
	if comp.Name != "" && comp.Version != "" {
		return fmt.Sprintf("%s %s", comp.Name, comp.Version)
	}
	return ""
}
