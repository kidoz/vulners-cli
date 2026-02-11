package matcher

import (
	"context"
	"log/slog"
	"strings"

	vulners "github.com/kidoz/go-vulners"
	"github.com/kidoz/vulners-cli/internal/intel"
	"github.com/kidoz/vulners-cli/internal/model"
)

// Enricher enriches govulncheck findings with Vulners intel data.
type Enricher struct {
	intel         intel.Client
	logger        *slog.Logger
	enableAIScore bool
}

// NewEnricher creates a new Enricher.
func NewEnricher(intelClient intel.Client, logger *slog.Logger) *Enricher {
	return &Enricher{intel: intelClient, logger: logger}
}

// WithAIScore enables on-demand AI score enrichment for findings that lack one.
func (e *Enricher) WithAIScore(enabled bool) *Enricher {
	e.enableAIScore = enabled
	return e
}

// Enrich takes govulncheck findings and adds Vulners exploit/severity data.
// It batch-fetches bulletins for efficiency when possible.
func (e *Enricher) Enrich(ctx context.Context, findings []model.Finding) []model.Finding {
	if e.intel == nil {
		return findings
	}

	// Collect all IDs to fetch in batch.
	var allIDs []string
	idToIndex := make(map[string][]int) // maps bulletin ID → finding indices
	for i, f := range findings {
		if f.VulnID == "" {
			continue
		}
		ids := []string{f.VulnID}
		ids = append(ids, f.Aliases...)
		for _, id := range ids {
			if !strings.HasPrefix(id, "CVE-") && !strings.HasPrefix(id, "GO-") {
				continue
			}
			allIDs = append(allIDs, id)
			idToIndex[id] = append(idToIndex[id], i)
		}
	}

	if len(allIDs) == 0 {
		return findings
	}

	// Try batch fetch first.
	bulletinMap, err := e.intel.GetMultipleBulletins(ctx, allIDs)
	if err != nil {
		e.logger.Debug("batch fetch failed, falling back to individual lookups", "error", err)
		return e.enrichIndividually(ctx, findings)
	}

	// Track which findings have been enriched.
	enriched := make(map[int]bool)
	for id, bulletin := range bulletinMap {
		indices := idToIndex[id]
		for _, i := range indices {
			if enriched[i] {
				continue
			}
			enrichFinding(&findings[i], &bulletin)
			enriched[i] = true
		}
	}

	// Optionally enrich with AI score for findings that lack one.
	if e.enableAIScore {
		e.enrichAIScores(ctx, findings)
	}

	return findings
}

func (e *Enricher) enrichAIScores(ctx context.Context, findings []model.Finding) {
	for i := range findings {
		if ctx.Err() != nil {
			return
		}
		if findings[i].AIScore != nil || findings[i].VulnID == "" {
			continue
		}
		score, err := e.intel.GetAIScore(ctx, findings[i].VulnID)
		if err != nil {
			e.logger.Debug("AI score enrichment failed", "id", findings[i].VulnID, "error", err)
			continue
		}
		if score == nil {
			continue
		}
		findings[i].AIScore = &score.Score
	}
}

func (e *Enricher) enrichIndividually(ctx context.Context, findings []model.Finding) []model.Finding {
	for i, f := range findings {
		if ctx.Err() != nil {
			e.logger.Debug("enrichment cancelled", "enriched_so_far", i)
			return findings
		}
		if f.VulnID == "" {
			continue
		}

		ids := []string{f.VulnID}
		ids = append(ids, f.Aliases...)

		for _, id := range ids {
			if !strings.HasPrefix(id, "CVE-") && !strings.HasPrefix(id, "GO-") {
				continue
			}

			bulletin, err := e.intel.GetBulletin(ctx, id)
			if err != nil {
				e.logger.Debug("enrichment lookup failed", "id", id, "error", err)
				continue
			}

			enrichFinding(&findings[i], bulletin)
			break
		}
	}

	return findings
}

func enrichFinding(f *model.Finding, bulletin *vulners.Bulletin) {
	rich := BulletinToFinding(bulletin, f.ComponentRef)
	if rich.CVSS > 0 {
		f.CVSS = rich.CVSS
		f.Severity = rich.Severity
	}
	if rich.HasExploit {
		f.HasExploit = true
	}
	if len(bulletin.CVEList) > 0 {
		f.Aliases = mergeAliases(f.Aliases, bulletin.CVEList)
	}
	if len(rich.References) > 0 {
		f.References = append(f.References, rich.References...)
	}
	if rich.EPSS != nil {
		f.EPSS = rich.EPSS
	}
	if rich.AIScore != nil {
		f.AIScore = rich.AIScore
	}
}

// mergeAliases combines existing and new aliases, deduplicating by value.
func mergeAliases(existing, incoming []string) []string {
	seen := make(map[string]bool, len(existing)+len(incoming))
	var merged []string
	for _, id := range existing {
		if !seen[id] {
			seen[id] = true
			merged = append(merged, id)
		}
	}
	for _, id := range incoming {
		if !seen[id] {
			seen[id] = true
			merged = append(merged, id)
		}
	}
	return merged
}
