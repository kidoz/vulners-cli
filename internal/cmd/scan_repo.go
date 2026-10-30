package cmd

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/kidoz/vulners-cli/internal/cache"
	"github.com/kidoz/vulners-cli/internal/intel"
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
	TopFindings   []model.Finding   `json:"topFindings,omitempty"`
	Truncated     bool              `json:"truncated,omitempty"`
	TotalFindings int               `json:"totalFindings,omitempty"`
	ImageMeta     *ImageMeta        `json:"imageMeta,omitempty"`
}

// ImageMeta provides image-specific context in scan output.
type ImageMeta struct {
	Distro      *DistroMeta `json:"distro,omitempty"`
	OSPackages  int         `json:"osPackages"`
	AppPackages int         `json:"appPackages"`
	AuditMode   string      `json:"auditMode"` // "hybrid", "sbom", "offline"
}

// DistroMeta is the JSON-friendly distro info for scan output.
type DistroMeta struct {
	Name    string `json:"name"`
	Version string `json:"version"`
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
	if !globals.Plan && !globals.Offline {
		findings, scanErr := scanGoRepoOnline(ctx, deps, logger, c.Path)
		if scanErr != nil {
			return scanErr
		}
		return finalizeScan(globals, c.Path, components, findings)
	}
	return scanComponents(ctx, globals, deps, store, logger, c.Path, components)
}

func scanGoRepoOnline(
	ctx context.Context,
	deps *Deps,
	logger *slog.Logger,
	path string,
) ([]model.Finding, error) {
	if deps.Intel == nil {
		return nil, usageErrorf("VULNERS_API_KEY is required for online scanning")
	}
	findings, err := intel.RunGovulncheck(ctx, path, logger)
	if err != nil {
		return nil, fmt.Errorf("running reachability analysis: %w", err)
	}
	return matcher.NewEnricher(deps.Intel, logger).Enrich(ctx, findings), nil
}

// PlanOutput describes what a scan would do without executing it.
type PlanOutput struct {
	Target         string            `json:"target"`
	Mode           string            `json:"mode"` // "online" or "offline"
	ComponentCount int               `json:"componentCount"`
	Ecosystems     map[string]int    `json:"ecosystems"`
	HasAPIKey      bool              `json:"hasApiKey"`
	Components     []model.Component `json:"components,omitempty"`
}

func scanComponents(
	ctx context.Context,
	globals *CLI,
	deps *Deps,
	store cache.Store,
	logger *slog.Logger,
	target string,
	components []model.Component,
) error {
	if globals.Plan {
		return writePlanOutput(globals, target, components, deps)
	}

	var findings []model.Finding
	var err error
	if globals.Offline {
		findings, err = scanOfflineComponents(ctx, store, components, logger)
	} else {
		if deps.Intel == nil {
			return usageErrorf("VULNERS_API_KEY is required for online scanning")
		}
		m := matcher.NewMatcher(deps.Intel, logger)
		findings, err = m.Match(ctx, components)
	}
	if err != nil {
		return err
	}
	return finalizeScan(globals, target, components, findings)
}

func writePlanOutput(globals *CLI, target string, components []model.Component, deps *Deps) error {
	ecosystems := make(map[string]int)
	for _, c := range components {
		t := c.Type
		if t == "" {
			t = "unknown"
		}
		ecosystems[t]++
	}

	mode := "online"
	if globals.Offline {
		mode = "offline"
	}

	plan := PlanOutput{
		Target:         target,
		Mode:           mode,
		ComponentCount: len(components),
		Ecosystems:     ecosystems,
		HasAPIKey:      deps.Intel != nil,
	}

	w, closer, err := outputWriter(globals)
	if err != nil {
		return err
	}
	defer func() { _ = closer() }()

	return writeIntelOutput(w, globals, "plan", plan, nil)
}

func scanOfflineComponents(
	ctx context.Context,
	store cache.Store,
	components []model.Component,
	_ *slog.Logger,
) ([]model.Finding, error) {
	meta, err := store.GetCollectionMeta(ctx)
	if err != nil {
		return nil, fmt.Errorf("checking offline data: %w", err)
	}
	if len(meta) == 0 {
		return nil, cache.ErrOfflineDataMissing
	}
	var findings []model.Finding
	for _, comp := range components {
		comp = matcher.NormalizeComponent(comp)
		if (comp.Name == "" || comp.Version == "") && comp.CPE == "" {
			continue
		}
		results, err := store.MatchBulletins(ctx, comp.Name, comp.Version, comp.CPE)
		if err != nil {
			return nil, fmt.Errorf("offline lookup for %s@%s: %w", comp.Name, comp.Version, err)
		}
		for _, b := range results {
			findings = append(findings, matcher.BulletinToFinding(&b, comp.Name+"@"+comp.Version))
		}
	}

	seen := make(map[string]struct{}, len(findings))
	deduped := findings[:0]
	for _, f := range findings {
		key := f.VulnID + "|" + f.ComponentRef
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		deduped = append(deduped, f)
	}
	return deduped, nil
}

func newPolicy(globals *CLI) (*policy.Policy, error) {
	if err := validateFailOn(globals.FailOn); err != nil {
		return nil, err
	}
	p := policy.New(globals.FailOn, globals.Ignore)
	if globals.VEX != "" {
		statements, err := policy.LoadVEX(globals.VEX)
		if err != nil {
			return nil, usageErrorf("loading VEX: %v", err)
		}
		p.VEXStatements = statements
	}
	return p, nil
}

func finalizeScan(globals *CLI, target string, components []model.Component, findings []model.Finding, imageMeta ...*ImageMeta) error {
	p, err := newPolicy(globals)
	if err != nil {
		return err
	}
	findings = p.Filter(findings, components)
	exitCode := p.ExitCode(findings)

	var meta *ImageMeta
	if len(imageMeta) > 0 {
		meta = imageMeta[0]
	}

	if writeErr := writeOutput(globals, target, components, findings, meta); writeErr != nil {
		return writeErr
	}

	if exitCode != model.ExitOK {
		return &model.ExitError{Code: exitCode}
	}
	return nil
}

func writeOutput(globals *CLI, target string, components []model.Component, findings []model.Finding, imageMeta *ImageMeta) (retErr error) {
	if globals.Agent {
		sortFindings(findings)
	}

	summary := summarize(components, findings)
	output := ScanOutput{
		SchemaVersion: "1.0.0",
		Target:        target,
		Components:    components,
		Findings:      findings,
		Summary:       summary,
		ImageMeta:     imageMeta,
	}

	if globals.SummaryOnly {
		output.Components = []model.Component{}
		output.Findings = []model.Finding{}
		top := topNFindings(findings, 5)
		if len(top) > 0 {
			output.TopFindings = top
		}
	}

	if !globals.SummaryOnly && globals.MaxFindings > 0 && len(findings) > globals.MaxFindings {
		output.Truncated = true
		output.TotalFindings = len(findings)
		output.Findings = findings[:globals.MaxFindings]
	}

	w, closer, err := outputWriter(globals)
	if err != nil {
		return err
	}
	defer func() {
		if closeErr := closer(); retErr == nil && closeErr != nil {
			retErr = fmt.Errorf("closing output: %w", closeErr)
		}
	}()

	reporter := report.New(model.OutputFormat(globals.Output))
	var out any = output
	if model.OutputFormat(globals.Output) == model.OutputJSON && len(globals.Fields) > 0 {
		projected, ferr := projectFields(output, globals.Fields)
		if ferr != nil {
			return ferr
		}
		out = projected
	}

	return reporter.Write(w, out)
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
