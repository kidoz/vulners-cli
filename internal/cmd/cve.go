package cmd

import (
	"context"
	"fmt"

	vulners "github.com/kidoz/go-vulners"
	"github.com/kidoz/vulners-cli/internal/cache"
)

// CVECmd looks up a CVE by ID.
type CVECmd struct {
	ID         string `arg:"" help:"CVE identifier (e.g. CVE-2021-44228)"`
	References bool   `help:"Include external references"`
	History    bool   `help:"Include change history"`
	Affected   bool   `help:"Include affected packages and CPE configurations"`
	Related    bool   `help:"Include related bulletins (exploits, patches) grouped by type"`
}

// CVEOutput wraps bulletin data with optional references, history, affected
// components and related bulletins.
type CVEOutput struct {
	Bulletin   *vulners.Bulletin                        `json:"bulletin"`
	References []string                                 `json:"references,omitempty"`
	History    []vulners.HistoryEntry                   `json:"history,omitempty"`
	Affected   *vulners.CVEAuditIssue                   `json:"affected,omitempty"`
	Related    map[string]map[string][]vulners.Bulletin `json:"related,omitempty"`
}

func (c *CVECmd) Run(ctx context.Context, globals *CLI, deps *Deps, store cache.Store) error {
	if err := validateNonScanFormat(globals.Output); err != nil {
		return err
	}

	w, closer, err := outputWriter(globals)
	if err != nil {
		return err
	}
	defer func() { _ = closer() }()

	if globals.Offline {
		bulletin, err := store.GetBulletin(ctx, c.ID)
		if err != nil {
			return fmt.Errorf("offline CVE lookup failed: %w", err)
		}
		return writeIntelOutput(w, globals, "cve", bulletin, nil)
	}

	if deps.Intel == nil {
		return fmt.Errorf("VULNERS_API_KEY is required for CVE lookup")
	}

	bulletin, err := deps.Intel.GetBulletin(ctx, c.ID)
	if err != nil {
		return fmt.Errorf("CVE lookup failed: %w", err)
	}

	// If no extra flag is set, output just the bulletin.
	if !c.References && !c.History && !c.Affected && !c.Related {
		return writeIntelOutput(w, globals, "cve", bulletin, nil)
	}

	output, err := c.enrich(ctx, deps, bulletin)
	if err != nil {
		return err
	}

	return writeIntelOutput(w, globals, "cve", output, nil)
}

// enrich fetches the optional references, history and affected components
// requested via flags and assembles the combined CVE output.
func (c *CVECmd) enrich(ctx context.Context, deps *Deps, bulletin *vulners.Bulletin) (CVEOutput, error) {
	output := CVEOutput{Bulletin: bulletin}

	if c.References {
		refs, err := deps.Intel.GetBulletinReferences(ctx, c.ID)
		if err != nil {
			return output, fmt.Errorf("fetching references: %w", err)
		}
		output.References = refs
	}

	if c.History {
		history, err := deps.Intel.GetBulletinHistory(ctx, c.ID)
		if err != nil {
			return output, fmt.Errorf("fetching history: %w", err)
		}
		output.History = history
	}

	if c.Affected {
		affected, err := deps.Intel.CVEAudit(ctx, c.ID)
		if err != nil {
			return output, fmt.Errorf("fetching affected components: %w", err)
		}
		output.Affected = affected
	}

	if c.Related {
		related, err := deps.Intel.GetBulletinWithReferences(ctx, c.ID)
		if err != nil {
			return output, fmt.Errorf("fetching related bulletins: %w", err)
		}
		output.Related = related.References
	}

	return output, nil
}
