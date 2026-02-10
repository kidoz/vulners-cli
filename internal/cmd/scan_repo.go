package cmd

import (
	"context"
	"fmt"
	"log/slog"
	"os"

	"github.com/kidoz/vulners-cli/internal/cache"
	"github.com/kidoz/vulners-cli/internal/inventory"
	"github.com/kidoz/vulners-cli/internal/matcher"
	"github.com/kidoz/vulners-cli/internal/model"
	"github.com/kidoz/vulners-cli/internal/policy"
	"github.com/kidoz/vulners-cli/internal/report"
)

// ScanRepoCmd scans a repository for vulnerabilities.
type ScanRepoCmd struct {
	Path string `arg:"" help:"Path to repository" default:"."`
}

// ScanOutput is the structured output for scan commands.
type ScanOutput struct {
	SchemaVersion string            `json:"schemaVersion"`
	Target        string            `json:"target"`
	Components    []model.Component `json:"components"`
	Findings      []model.Finding   `json:"findings"`
	Summary       ScanSummary       `json:"summary"`
}

// ScanSummary summarizes scan results.
type ScanSummary struct {
	ComponentCount int `json:"componentCount"`
	FindingCount   int `json:"findingCount"`
	Critical       int `json:"critical"`
	High           int `json:"high"`
	Medium         int `json:"medium"`
	Low            int `json:"low"`
	ExploitedCount int `json:"exploitedCount,omitempty"`
	HighEPSSCount  int `json:"highEpssCount,omitempty"`
}

func (c *ScanRepoCmd) Run(ctx context.Context, globals *CLI, deps *Deps, store cache.Store, logger *slog.Logger) error {
	collector := &inventory.GoModCollector{}
	components, err := collector.Collect(ctx, c.Path)
	if err != nil {
		return fmt.Errorf("collecting inventory: %w", err)
	}

	logger.Info("inventory collected", "components", len(components))

	var findings []model.Finding
	if globals.Offline {
		findings, err = c.scanOffline(ctx, store, components, logger)
	} else {
		findings, err = c.scanOnline(ctx, deps, components, logger)
	}
	if err != nil {
		return err
	}

	return finalizeScan(globals, c.Path, components, findings)
}

func (c *ScanRepoCmd) scanOnline(
	ctx context.Context,
	deps *Deps,
	components []model.Component,
	logger *slog.Logger,
) ([]model.Finding, error) {
	if deps.Intel == nil {
		return nil, fmt.Errorf("VULNERS_API_KEY is required for online scanning")
	}

	m := matcher.NewMatcher(deps.Intel, logger)
	return m.Match(ctx, components)
}

func (c *ScanRepoCmd) scanOffline(
	ctx context.Context,
	store cache.Store,
	components []model.Component,
	logger *slog.Logger,
) ([]model.Finding, error) {
	return scanOfflineComponents(ctx, store, components, logger)
}

func scanOfflineComponents(
	ctx context.Context,
	store cache.Store,
	components []model.Component,
	logger *slog.Logger,
) ([]model.Finding, error) {
	// Verify that at least one collection has been synced.
	// NopStore also returns ErrOfflineDataMissing here, so no type assertion needed.
	meta, err := store.GetCollectionMeta(ctx)
	if err != nil {
		return nil, fmt.Errorf("checking offline data: %w", err)
	}
	if len(meta) == 0 {
		return nil, cache.ErrOfflineDataMissing
	}
	var findings []model.Finding
	for _, comp := range components {
		results, _, err := store.SearchBulletins(ctx, comp.Name+" "+comp.Version, 20, 0)
		if err != nil {
			logger.Warn("offline search failed", "component", comp.Name, "error", err)
			continue
		}
		for _, b := range results {
			severity := "unknown"
			var cvss float64
			if b.CVSS != nil {
				cvss = b.CVSS.Score
				severity = model.ScoreSeverity(cvss)
			}

			findings = append(findings, model.Finding{
				VulnID:       b.ID,
				Aliases:      b.CVEList,
				Severity:     severity,
				CVSS:         cvss,
				ComponentRef: comp.Name + "@" + comp.Version,
			})
		}
	}

	return findings, nil
}

func newPolicy(globals *CLI) (*policy.Policy, error) {
	p := policy.New(globals.FailOn, globals.Ignore)
	if globals.VEX != "" {
		statuses, err := policy.LoadVEX(globals.VEX)
		if err != nil {
			return nil, err
		}
		p.VEXStatuses = statuses
	}
	return p, nil
}

func finalizeScan(globals *CLI, target string, components []model.Component, findings []model.Finding) error {
	p, err := newPolicy(globals)
	if err != nil {
		return err
	}
	findings = p.Filter(findings)
	exitCode := p.ExitCode(findings)

	if writeErr := writeOutput(globals, target, components, findings); writeErr != nil {
		return writeErr
	}

	if exitCode != model.ExitOK {
		return &model.ExitError{Code: exitCode}
	}
	return nil
}

func writeOutput(globals *CLI, target string, components []model.Component, findings []model.Finding) error {
	output := ScanOutput{
		SchemaVersion: "1.0.0",
		Target:        target,
		Components:    components,
		Findings:      findings,
		Summary:       summarize(components, findings),
	}

	reporter := report.New(model.OutputFormat(globals.Output))
	return reporter.Write(os.Stdout, output)
}

func summarize(components []model.Component, findings []model.Finding) ScanSummary {
	s := ScanSummary{
		ComponentCount: len(components),
		FindingCount:   len(findings),
	}
	for _, f := range findings {
		switch f.Severity {
		case "critical":
			s.Critical++
		case "high":
			s.High++
		case "medium":
			s.Medium++
		case "low":
			s.Low++
		}
		if f.WildExploited || f.HasExploit {
			s.ExploitedCount++
		}
		if f.EPSS != nil && *f.EPSS >= 0.1 {
			s.HighEPSSCount++
		}
	}
	return s
}
