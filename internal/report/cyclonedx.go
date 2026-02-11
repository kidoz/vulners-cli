package report

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"time"

	cdx "github.com/CycloneDX/cyclonedx-go"
)

// CycloneDXReporter writes output as a CycloneDX SBOM with vulnerability info.
type CycloneDXReporter struct{}

type cdxInput struct {
	Target     string      `json:"target"`
	Components []cdxCompIn `json:"components"`
	Findings   []cdxFindIn `json:"findings"`
}

type cdxCompIn struct {
	Type    string `json:"type"`
	Name    string `json:"name"`
	Version string `json:"version"`
	PURL    string `json:"purl"`
	CPE     string `json:"cpe"`
}

type cdxFindIn struct {
	VulnID       string  `json:"vulnID"`
	Severity     string  `json:"severity"`
	CVSS         float64 `json:"cvss"`
	ComponentRef string  `json:"componentRef"`
	Fix          string  `json:"fix"`
}

func (r *CycloneDXReporter) Write(w io.Writer, data any) error {
	raw, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("marshaling data for CycloneDX: %w", err)
	}

	var input cdxInput
	if err := json.Unmarshal(raw, &input); err != nil {
		return fmt.Errorf("preparing CycloneDX data: %w", err)
	}

	bom := cdx.NewBOM()
	uid, err := generateUUID()
	if err != nil {
		return err
	}
	bom.SerialNumber = "urn:uuid:" + uid
	bom.Version = 1
	bom.Metadata = &cdx.Metadata{
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Tools: &cdx.ToolsChoice{
			Components: &[]cdx.Component{
				{Type: cdx.ComponentTypeApplication, Name: "vulners-cli", Version: Version},
			},
		},
	}

	components, bomRefMap := buildCDXComponents(input.Components)
	bom.Components = &components
	vulns := buildCDXVulnerabilities(input.Findings, bomRefMap)
	bom.Vulnerabilities = &vulns

	encoder := cdx.NewBOMEncoder(w, cdx.BOMFileFormatJSON)
	encoder.SetPretty(true)
	if err := encoder.Encode(bom); err != nil {
		return fmt.Errorf("encoding CycloneDX: %w", err)
	}
	return nil
}

func buildCDXComponents(inputs []cdxCompIn) ([]cdx.Component, map[string]string) {
	bomRefMap := make(map[string]string)
	var components []cdx.Component
	for i, c := range inputs {
		bomRef := fmt.Sprintf("comp-%d", i)
		bomRefMap[c.Name+"@"+c.Version] = bomRef
		comp := cdx.Component{
			BOMRef:  bomRef,
			Type:    cdxComponentType(c.Type),
			Name:    c.Name,
			Version: c.Version,
		}
		if c.PURL != "" {
			comp.PackageURL = c.PURL
		}
		if c.CPE != "" {
			comp.CPE = c.CPE
		}
		components = append(components, comp)
	}
	return components, bomRefMap
}

func buildCDXVulnerabilities(findings []cdxFindIn, bomRefMap map[string]string) []cdx.Vulnerability {
	var vulns []cdx.Vulnerability
	for _, f := range findings {
		v := cdx.Vulnerability{
			ID: f.VulnID,
			Ratings: &[]cdx.VulnerabilityRating{
				{Score: &f.CVSS, Severity: cdxSeverity(f.Severity), Method: cdx.ScoringMethodCVSSv3},
			},
		}
		if f.ComponentRef != "" {
			ref := f.ComponentRef
			if bomRef, ok := bomRefMap[ref]; ok {
				ref = bomRef
			}
			v.Affects = &[]cdx.Affects{{Ref: ref}}
		}
		vulns = append(vulns, v)
	}
	return vulns
}

func cdxSeverity(s string) cdx.Severity {
	switch s {
	case "critical":
		return cdx.SeverityCritical
	case "high":
		return cdx.SeverityHigh
	case "medium":
		return cdx.SeverityMedium
	case "low":
		return cdx.SeverityLow
	default:
		return cdx.SeverityUnknown
	}
}

// cdxComponentType maps internal type strings to valid CycloneDX component types.
func cdxComponentType(t string) cdx.ComponentType {
	switch t {
	case "library", "go-module", "go", "npm", "pip", "maven", "gem", "cargo", "nuget":
		return cdx.ComponentTypeLibrary
	case "framework":
		return cdx.ComponentTypeFramework
	case "application":
		return cdx.ComponentTypeApplication
	case "firmware":
		return cdx.ComponentTypeFirmware
	case "operating-system":
		return cdx.ComponentTypeOS
	default:
		return cdx.ComponentTypeLibrary
	}
}

// generateUUID returns a random UUID v4 string.
func generateUUID() (string, error) {
	var uuid [16]byte
	if _, err := rand.Read(uuid[:]); err != nil {
		return "", fmt.Errorf("generating UUID: %w", err)
	}
	uuid[6] = (uuid[6] & 0x0f) | 0x40 // version 4
	uuid[8] = (uuid[8] & 0x3f) | 0x80 // variant 10
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		uuid[0:4], uuid[4:6], uuid[6:8], uuid[8:10], uuid[10:16]), nil
}
