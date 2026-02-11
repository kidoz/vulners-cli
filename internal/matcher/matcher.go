package matcher

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

	"github.com/kidoz/vulners-cli/internal/intel"
	"github.com/kidoz/vulners-cli/internal/model"
)

// searchLimit is the maximum number of bulletins to fetch per component.
// High enough to avoid missing vulns for popular packages (e.g. OpenSSL).
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
	var findings []model.Finding
	var skipped int

	for _, comp := range components {
		comp = NormalizeComponent(comp)
		query := buildQuery(comp)
		if query == "" {
			continue
		}

		m.logger.Debug("querying vulners", "component", comp.Name, "version", comp.Version)

		result, err := m.intel.Search(ctx, query, searchLimit, 0)
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
			findings = append(findings, BulletinToFinding(&b, comp.Name+"@"+comp.Version))
		}
	}

	if skipped > 0 {
		m.logger.Warn("components skipped due to search errors",
			"skipped", skipped, "total", len(components))
	}

	// If every component lookup failed, surface an error instead of
	// silently returning zero findings (false negative).
	queried := len(components) - skipped
	if queried == 0 && len(components) > 0 {
		return nil, fmt.Errorf("all %d component lookups failed; results would be empty", len(components))
	}

	return findings, nil
}

// querySpecialChars are characters that have meaning in Vulners query syntax.
var querySpecialChars = strings.NewReplacer(
	`\`, `\\`,
	`"`, `\"`,
	`:`, `\:`,
	`(`, `\(`,
	`)`, `\)`,
	`[`, `\[`,
	`]`, `\]`,
)

func buildQuery(comp model.Component) string {
	if comp.CPE != "" {
		return fmt.Sprintf("affectedSoftware.cpe:%q", comp.CPE)
	}
	if comp.Name != "" && comp.Version != "" {
		// Quoted field values: characters inside double quotes are literal in
		// Lucene-like query parsers, so use raw values. Unquoted fallback
		// needs escaping for special chars.
		escaped := querySpecialChars.Replace(comp.Name)
		escapedVer := querySpecialChars.Replace(comp.Version)
		return fmt.Sprintf("affectedSoftware.name:%q AND affectedSoftware.version:%q OR %s %s",
			comp.Name, comp.Version, escaped, escapedVer)
	}
	return ""
}
