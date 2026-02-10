package cmd

import (
	"context"
	"fmt"
	"log/slog"
	"os"

	vulners "github.com/kidoz/go-vulners"
	"github.com/kidoz/vulners-cli/internal/cache"
	"github.com/kidoz/vulners-cli/internal/inventory"
	"github.com/kidoz/vulners-cli/internal/model"
)

// ScanSBOMCmd scans an SBOM file for vulnerabilities.
type ScanSBOMCmd struct {
	File   string `arg:"" help:"Path to SBOM file"`
	Format string `help:"SBOM format (cyclonedx, spdx)" enum:"cyclonedx,spdx" default:"cyclonedx"`
}

func (c *ScanSBOMCmd) Run(ctx context.Context, globals *CLI, deps *Deps, store cache.Store, logger *slog.Logger) error {
	collector := &inventory.SBOMCollector{Format: c.Format}
	components, err := collector.Collect(ctx, c.File)
	if err != nil {
		return fmt.Errorf("parsing SBOM: %w", err)
	}

	logger.Info("SBOM parsed", "components", len(components), "format", c.Format)

	var findings []model.Finding
	if globals.Offline {
		var offErr error
		findings, offErr = scanOfflineComponents(ctx, store, components, logger)
		if offErr != nil {
			return offErr
		}
	} else {
		if deps.Intel == nil {
			return fmt.Errorf("VULNERS_API_KEY is required for online scanning")
		}
		f, openErr := os.Open(c.File)
		if openErr != nil {
			return fmt.Errorf("opening SBOM for audit: %w", openErr)
		}
		defer func() { _ = f.Close() }()

		result, auditErr := deps.Intel.SBOMAudit(ctx, f)
		if auditErr != nil {
			return fmt.Errorf("SBOM audit: %w", auditErr)
		}
		findings = convertSBOMFindings(result.Packages)
	}

	return finalizeScan(globals, c.File, components, findings)
}

func convertSBOMFindings(packages []vulners.SBOMPackageResult) []model.Finding {
	var findings []model.Finding
	for _, pkg := range packages {
		ref := pkg.Package + "@" + pkg.Version
		fix := ""
		if pkg.FixedVersion != nil {
			fix = *pkg.FixedVersion
		}
		for _, adv := range pkg.ApplicableAdvisories {
			var cvss float64
			if adv.Metrics != nil && adv.Metrics.CVSS != nil {
				cvss = adv.Metrics.CVSS.Score
			}
			var epss *float64
			if len(adv.EPSS) > 0 && adv.EPSS[0].Epss > 0 {
				v := adv.EPSS[0].Epss
				epss = &v
			}
			var hasExploit, wildExploited bool
			if adv.Exploitation != nil {
				wildExploited = adv.Exploitation.WildExploited
				hasExploit = wildExploited
			}
			if adv.Type == "exploit" || len(adv.Exploits) > 0 {
				hasExploit = true
			}
			var aiScore *float64
			if adv.AIScore != nil {
				s := adv.AIScore.Score
				aiScore = &s
			}
			findings = append(findings, model.Finding{
				VulnID:        adv.ID,
				Severity:      model.ScoreSeverity(cvss),
				CVSS:          cvss,
				EPSS:          epss,
				AIScore:       aiScore,
				HasExploit:    hasExploit,
				WildExploited: wildExploited,
				ComponentRef:  ref,
				Fix:           fix,
				References:    adv.References,
			})
		}
	}
	return findings
}
