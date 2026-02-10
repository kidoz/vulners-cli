package inventory

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"regexp"

	cdx "github.com/CycloneDX/cyclonedx-go"

	"github.com/kidoz/vulners-cli/internal/model"
)

// validImageRef matches valid Docker image references and local file paths:
// [registry/]name[:tag][@digest] or ./path/to/file — no shell metacharacters.
var validImageRef = regexp.MustCompile(`^[a-zA-Z0-9./][a-zA-Z0-9._/:@\-]*$`)

// SyftCollector collects components from a container image using syft.
type SyftCollector struct{}

func (c *SyftCollector) Collect(ctx context.Context, imageRef string) ([]model.Component, error) {
	if imageRef == "" {
		return nil, fmt.Errorf("image reference must not be empty")
	}
	if !validImageRef.MatchString(imageRef) {
		return nil, fmt.Errorf("invalid image reference %q: contains disallowed characters", imageRef)
	}

	if _, err := exec.LookPath("syft"); err != nil {
		return nil, fmt.Errorf("syft not found in PATH; install from https://github.com/anchore/syft")
	}

	var stdout, stderr bytes.Buffer
	cmd := exec.CommandContext(ctx, "syft", imageRef, "-o", "cyclonedx-json", "--quiet")
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("syft failed: %w: %s", err, stderr.String())
	}

	return parseCycloneDXReader(&stdout)
}

func parseCycloneDXReader(r *bytes.Buffer) ([]model.Component, error) {
	var bom cdx.BOM
	decoder := cdx.NewBOMDecoder(r, cdx.BOMFileFormatJSON)
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
