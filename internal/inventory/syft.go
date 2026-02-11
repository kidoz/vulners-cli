package inventory

import (
	"bytes"
	"context"
	"fmt"
	"strings"

	cdx "github.com/CycloneDX/cyclonedx-go"

	// Explicitly importing full paths for syft components
	syftPkg "github.com/anchore/syft/syft"
	syftFormatPkg "github.com/anchore/syft/syft/format"
	syftFormatCdxjsonPkg "github.com/anchore/syft/syft/format/cyclonedxjson"
	syftSbomPkg "github.com/anchore/syft/syft/sbom"

	"github.com/kidoz/vulners-cli/internal/model"
)

// DistroInfo holds the detected OS distribution from a container image SBOM.
type DistroInfo struct {
	Name    string `json:"name"`    // "alpine", "debian", "ubuntu", "centos", etc.
	Version string `json:"version"` // "3.18", "12", "22.04"
}

// SBOMResult holds both the raw SBOM bytes and parsed components from syft.
type SBOMResult struct {
	Components []model.Component
	RawSBOM    []byte
	Distro     *DistroInfo
}

// SyftCollector collects components from a container image using syft.
type SyftCollector struct{}

// CollectSBOM runs syft and returns both the raw CycloneDX SBOM and parsed components.
func (c *SyftCollector) CollectSBOM(ctx context.Context, imageRef string) (*SBOMResult, error) {
	if imageRef == "" {
		return nil, fmt.Errorf("image reference must not be empty")
	}

	// Use syft library to get source and create SBOM
	src, err := syftPkg.GetSource(ctx, imageRef, &syftPkg.GetSourceConfig{})
	if err != nil {
		return nil, fmt.Errorf("error getting syft source for image %q: %w", imageRef, err)
	}

	// Create the SBOM with default configuration
	sbom, err := syftPkg.CreateSBOM(ctx, src, syftPkg.DefaultCreateSBOMConfig())
	if err != nil {
		return nil, fmt.Errorf("error creating SBOM for image %q: %w", imageRef, err)
	}

	// Find the CycloneDX JSON encoder
	var cyclonedxEncoder syftSbomPkg.FormatEncoder
	for _, encoder := range syftFormatPkg.Encoders() {
		if encoder.ID() == syftFormatCdxjsonPkg.ID {
			cyclonedxEncoder = encoder
			break
		}
	}

	if cyclonedxEncoder == nil {
		return nil, fmt.Errorf("CycloneDX JSON encoder not found in syft library")
	}

	// Encode the syft.SBOM to CycloneDX JSON
	var rawSBOM bytes.Buffer
	if err := cyclonedxEncoder.Encode(&rawSBOM, *sbom); err != nil {
		return nil, fmt.Errorf("error encoding SBOM to CycloneDX JSON: %w", err)
	}

	result, err := parseCycloneDXBOM(bytes.NewReader(rawSBOM.Bytes()))
	if err != nil {
		return nil, err
	}
	result.RawSBOM = rawSBOM.Bytes()

	return result, nil
}

// Collect runs syft and returns parsed components (implements the Collector pattern).
func (c *SyftCollector) Collect(ctx context.Context, imageRef string) ([]model.Component, error) {
	result, err := c.CollectSBOM(ctx, imageRef)
	if err != nil {
		return nil, err
	}
	return result.Components, nil
}

// ParseCycloneDXBytes parses raw CycloneDX JSON bytes and returns an SBOMResult
// containing both the raw bytes and parsed components.
func ParseCycloneDXBytes(data []byte) (*SBOMResult, error) {
	result, err := parseCycloneDXBOM(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	raw := make([]byte, len(data))
	copy(raw, data)
	result.RawSBOM = raw
	return result, nil
}

// parseCycloneDXBOM decodes a CycloneDX BOM and extracts components and distro info.
func parseCycloneDXBOM(r *bytes.Reader) (*SBOMResult, error) {
	var bom cdx.BOM
	decoder := cdx.NewBOMDecoder(r, cdx.BOMFileFormatJSON)
	if err := decoder.Decode(&bom); err != nil {
		return nil, fmt.Errorf("decoding CycloneDX SBOM: %w", err)
	}

	result := &SBOMResult{}

	// Extract distro info from metadata component (type "operating-system").
	if bom.Metadata != nil && bom.Metadata.Component != nil {
		mc := bom.Metadata.Component
		if mc.Type == cdx.ComponentTypeOS {
			result.Distro = &DistroInfo{
				Name:    strings.ToLower(mc.Name),
				Version: mc.Version,
			}
		}
	}

	if bom.Components != nil {
		for _, comp := range *bom.Components {
			c := model.Component{
				Type:    string(comp.Type),
				Name:    comp.Name,
				Version: comp.Version,
			}
			if comp.PackageURL != "" {
				c.PURL = comp.PackageURL
				c.Ecosystem = ecosystemFromPURL(comp.PackageURL)
			}
			if comp.CPE != "" {
				c.CPE = comp.CPE
			}
			result.Components = append(result.Components, c)
		}
	}

	return result, nil
}

// osEcosystems are PURL schemes that correspond to OS-level package managers.
var osEcosystems = map[string]bool{
	"apk": true,
	"deb": true,
	"rpm": true,
}

// IsOSEcosystem returns true if the ecosystem represents an OS-level package manager.
func IsOSEcosystem(ecosystem string) bool {
	return osEcosystems[ecosystem]
}

// ecosystemFromPURL extracts the ecosystem (package type) from a PURL string.
// e.g. "pkg:apk/alpine/musl@1.2.4" → "apk"
func ecosystemFromPURL(purl string) string {
	// PURL format: pkg:<type>/...
	if !strings.HasPrefix(purl, "pkg:") {
		return ""
	}
	rest := purl[4:]
	if idx := strings.IndexByte(rest, '/'); idx > 0 {
		return rest[:idx]
	}
	return ""
}
