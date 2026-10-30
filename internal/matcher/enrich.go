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
	seenIDs := make(map[string]bool)
	for i := range findings {
		for _, id := range candidateIDs(&findings[i]) {
			if seenIDs[id] {
				continue
			}
			seenIDs[id] = true
			allIDs = append(allIDs, id)
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

	// Batch responses omit IDs Vulners does not know, such as GO-* advisories.
	// Retry those findings individually so their CVE aliases can be used.
	for i := range findings {
		if e.enrichFromMap(&findings[i], bulletinMap) {
			continue
		}
		if ctx.Err() != nil {
			e.logger.Debug("enrichment cancelled", "enriched_so_far", i)
			break
		}
		e.enrichFindingIndividually(ctx, &findings[i])
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
		if findings[i].AIScore != nil {
			continue
		}
		ids := candidateIDs(&findings[i])
		if len(ids) == 0 {
			continue
		}
		score, err := e.intel.GetAIScore(ctx, ids[0])
		if err != nil {
			e.logger.Debug("AI score enrichment failed", "id", ids[0], "error", err)
			continue
		}
		if score == nil {
			continue
		}
		findings[i].AIScore = &score.Value
	}
}

func (e *Enricher) enrichIndividually(ctx context.Context, findings []model.Finding) []model.Finding {
	for i := range findings {
		if ctx.Err() != nil {
			e.logger.Debug("enrichment cancelled", "enriched_so_far", i)
			return findings
		}
		e.enrichFindingIndividually(ctx, &findings[i])
	}

	return findings
}

func (e *Enricher) enrichFindingIndividually(ctx context.Context, f *model.Finding) {
	for _, id := range candidateIDs(f) {
		bulletin, err := e.intel.GetBulletin(ctx, id)
		if err != nil {
			e.logger.Debug("enrichment lookup failed", "id", id, "error", err)
			continue
		}

		enrichFinding(f, bulletin)
		return
	}
}

// candidateIDs orders enrichment lookups by preference: CVE aliases first,
// then the govulncheck GO-* advisory ID. Vulners resolves CVEs but usually
// does not know Go advisory IDs.
func candidateIDs(f *model.Finding) []string {
	ids := make([]string, 0, len(f.Aliases)+1)
	seen := make(map[string]bool, len(f.Aliases)+1)

	add := func(id string) {
		if !strings.HasPrefix(id, "CVE-") && !strings.HasPrefix(id, "GO-") {
			return
		}
		if seen[id] {
			return
		}
		seen[id] = true
		ids = append(ids, id)
	}

	for _, id := range f.Aliases {
		add(id)
	}
	add(f.VulnID)

	return ids
}

func (e *Enricher) enrichFromMap(f *model.Finding, bulletins map[string]vulners.Bulletin) bool {
	for _, id := range candidateIDs(f) {
		if bulletin, ok := bulletins[id]; ok {
			enrichFinding(f, &bulletin)
			return true
		}
	}
	return false
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
