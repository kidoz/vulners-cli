package inventory

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	cdx "github.com/CycloneDX/cyclonedx-go"

	"github.com/kidoz/vulners-cli/internal/model"
)

// SBOMCollector collects components from CycloneDX or SPDX SBOM files.
type SBOMCollector struct {
	Format string // "cyclonedx" or "spdx"
}

func (c *SBOMCollector) Collect(_ context.Context, target string) ([]model.Component, error) {
	switch strings.ToLower(c.Format) {
	case "cyclonedx", "cdx":
		return parseCycloneDX(target)
	case "spdx":
		return parseSPDX(target)
	default:
		return nil, fmt.Errorf("unsupported SBOM format: %s (use cyclonedx or spdx)", c.Format)
	}
}

func parseCycloneDX(path string) ([]model.Component, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("opening SBOM: %w", err)
	}
	defer func() { _ = f.Close() }()

	var bom cdx.BOM
	decoder := cdx.NewBOMDecoder(f, cdx.BOMFileFormatJSON)
	if err := decoder.Decode(&bom); err != nil {
		return nil, fmt.Errorf("decoding CycloneDX SBOM: %w", err)
	}

	var components []model.Component
	if bom.Components != nil {
		for _, comp := range *bom.Components {
			c := model.Component{
				Type:    string(comp.Type),
				Name:    comp.Name,
				Version: comp.Version,
			}
			if comp.PackageURL != "" {
				c.PURL = comp.PackageURL
			}
			if comp.CPE != "" {
				c.CPE = comp.CPE
			}
			components = append(components, c)
		}
	}

	return components, nil
}

func parseSPDX(path string) ([]model.Component, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading SPDX SBOM: %w", err)
	}

	// Minimal SPDX JSON parsing for packages.
	var doc struct {
		Packages []struct {
			Name         string `json:"name"`
			Version      string `json:"versionInfo"`
			ExternalRefs []struct {
				Category string `json:"referenceCategory"`
				Type     string `json:"referenceType"`
				Locator  string `json:"referenceLocator"`
			} `json:"externalRefs"`
		} `json:"packages"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("decoding SPDX SBOM: %w", err)
	}

	var components []model.Component
	for _, pkg := range doc.Packages {
		if pkg.Name == "" {
			continue
		}
		c := model.Component{
			Type:      "library",
			Name:      pkg.Name,
			Version:   pkg.Version,
			Locations: []string{path},
		}
		for _, ref := range pkg.ExternalRefs {
			if ref.Type == "purl" {
				c.PURL = ref.Locator
				break
			}
		}
		components = append(components, c)
	}

	return components, nil
}
