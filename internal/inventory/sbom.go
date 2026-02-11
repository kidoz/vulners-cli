package inventory

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"

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
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("opening SBOM: %w", err)
	}
	result, err := ParseCycloneDXBytes(data)
	if err != nil {
		return nil, err
	}
	return result.Components, nil
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
