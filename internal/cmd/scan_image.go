package cmd

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"strings"

	vulners "github.com/kidoz/go-vulners"

	"github.com/kidoz/vulners-cli/internal/cache"
	"github.com/kidoz/vulners-cli/internal/inventory"
	"github.com/kidoz/vulners-cli/internal/model"
)

// ScanImageCmd scans a container image and generates an SBOM.
type ScanImageCmd struct {
	Image  string `arg:"" help:"Image reference (e.g. alpine:3.18, ./image.tar)"`
	Distro string `help:"Override auto-detected distro (format: name/version, e.g. alpine/3.18)" name:"distro" default:""`
}

func (c *ScanImageCmd) Run(ctx context.Context, globals *CLI, deps *Deps, store cache.Store, logger *slog.Logger) error {
	collector := &inventory.SyftCollector{}
	result, err := collector.CollectSBOM(ctx, c.Image)
	if err != nil {
		return fmt.Errorf("collecting image inventory: %w", err)
	}

	// Apply --distro override if provided.
	if c.Distro != "" {
		di, parseErr := parseDistroFlag(c.Distro)
		if parseErr != nil {
			return parseErr
		}
		result.Distro = di
	}

	logger.Info("image scanned",
		"components", len(result.Components),
		"image", c.Image,
		"distro", result.Distro,
	)

	// Plan and offline modes use component-based scanning.
	if globals.Plan || globals.Offline {
		return scanComponents(ctx, globals, deps, store, logger, c.Image, result.Components)
	}

	// Online: use hybrid matching when distro is detected.
	if deps.Intel == nil {
		return fmt.Errorf("VULNERS_API_KEY is required for online scanning")
	}

	findings, auditMode, err := c.scanImageOnline(ctx, deps, logger, result)
	if err != nil {
		return err
	}

	osComps, appComps := splitByEcosystem(result.Components)
	meta := buildImageMeta(result.Distro, len(osComps), len(appComps), auditMode)

	return finalizeScan(globals, c.Image, result.Components, findings, meta)
}

// scanImageOnline performs hybrid matching: LinuxAudit for OS packages when distro
// is detected, SBOMAudit for remaining packages. Returns findings and the audit mode used.
func (c *ScanImageCmd) scanImageOnline(
	ctx context.Context,
	deps *Deps,
	logger *slog.Logger,
	result *inventory.SBOMResult,
) ([]model.Finding, string, error) {
	osComps, appComps := splitByEcosystem(result.Components)
	auditMode := "sbom"

	// If we have a distro and OS packages, use LinuxAudit for the OS packages.
	var findings []model.Finding
	if result.Distro != nil && len(osComps) > 0 {
		logger.Info("using LinuxAudit for OS packages",
			"distro", result.Distro.Name,
			"version", result.Distro.Version,
			"osPackages", len(osComps),
		)
		pkgs := formatOSPackages(osComps)
		auditResult, err := deps.Intel.LinuxAudit(ctx, result.Distro.Name, result.Distro.Version, pkgs)
		if err != nil {
			logger.Warn("LinuxAudit failed, falling back to SBOMAudit for all packages", "error", err)
			// Fall through to SBOMAudit for everything.
			osComps = nil
			appComps = result.Components
		} else {
			auditMode = "hybrid"
			findings = append(findings, convertAuditFindings(auditResult)...)
		}
	} else {
		// No distro or no OS packages: treat everything as app packages.
		appComps = result.Components
	}

	// Send the full SBOM to SBOMAudit for application packages.
	// The SBOMAudit API handles all package types; the LinuxAudit findings above
	// give us more accurate results for OS packages specifically.
	if len(appComps) > 0 || len(osComps) == 0 {
		sbomReader := bytes.NewReader(result.RawSBOM)
		sbomResult, err := deps.Intel.SBOMAudit(ctx, sbomReader)
		if err != nil {
			return nil, "", fmt.Errorf("SBOM audit: %w", err)
		}
		sbomFindings := convertSBOMFindings(sbomResult.Packages)

		if len(findings) > 0 {
			// Merge: only add SBOMAudit findings for non-OS packages to avoid duplicates.
			osCompSet := make(map[string]bool, len(osComps))
			for _, c := range osComps {
				osCompSet[c.Name+"@"+c.Version] = true
			}
			for _, f := range sbomFindings {
				if !osCompSet[f.ComponentRef] {
					findings = append(findings, f)
				}
			}
		} else {
			findings = sbomFindings
		}
	}

	return findings, auditMode, nil
}

// splitByEcosystem separates components into OS packages and application packages.
func splitByEcosystem(components []model.Component) (osComps, appComps []model.Component) {
	for _, c := range components {
		if inventory.IsOSEcosystem(c.Ecosystem) {
			osComps = append(osComps, c)
		} else {
			appComps = append(appComps, c)
		}
	}
	return
}

// formatOSPackages converts components to the "name=version" format expected by LinuxAudit.
func formatOSPackages(comps []model.Component) []string {
	pkgs := make([]string, 0, len(comps))
	for _, c := range comps {
		pkgs = append(pkgs, c.Name+"="+c.Version)
	}
	return pkgs
}

// convertAuditFindings converts a Vulners AuditResult to model findings.
func convertAuditFindings(result *vulners.AuditResult) []model.Finding {
	var findings []model.Finding
	for _, v := range result.Vulnerabilities {
		var cvss float64
		if v.CVSS != nil {
			cvss = v.CVSS.Score
		}
		ref := v.Package
		if v.Version != "" {
			ref = v.Package + "@" + v.Version
		}
		findings = append(findings, model.Finding{
			VulnID:       v.BulletinID,
			Aliases:      v.CVEList,
			Severity:     model.ScoreSeverity(cvss),
			CVSS:         cvss,
			ComponentRef: ref,
			Fix:          v.Fix,
		})
	}
	return findings
}

// buildImageMeta creates an ImageMeta from scan results.
func buildImageMeta(distro *inventory.DistroInfo, osCount, appCount int, auditMode string) *ImageMeta {
	meta := &ImageMeta{
		OSPackages:  osCount,
		AppPackages: appCount,
		AuditMode:   auditMode,
	}
	if distro != nil {
		meta.Distro = &DistroMeta{
			Name:    distro.Name,
			Version: distro.Version,
		}
	}
	return meta
}

// parseDistroFlag parses a "name/version" distro string.
func parseDistroFlag(s string) (*inventory.DistroInfo, error) {
	parts := strings.SplitN(s, "/", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return nil, fmt.Errorf("invalid --distro format %q: expected name/version (e.g. alpine/3.18)", s)
	}
	return &inventory.DistroInfo{
		Name:    strings.ToLower(parts[0]),
		Version: parts[1],
	}, nil
}
