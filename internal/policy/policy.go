package policy

import (
	"strings"

	"github.com/kidoz/vulners-cli/internal/model"
)

// Policy determines which findings matter and what exit code to return.
type Policy struct {
	FailOn        model.SeverityLevel
	IgnoreIDs     map[string]bool
	VEXStatements map[string][]VEXStatement
}

// normID normalizes a vulnerability identifier for case-insensitive matching.
// Vulnerability IDs (CVE-..., RHSA-..., GHSA-...) are conventionally uppercase,
// but users frequently type them lowercase; normalize both sides to uppercase
// so --ignore cve-2021-44228 matches a finding carrying CVE-2021-44228.
func normID(id string) string {
	return strings.ToUpper(id)
}

// New creates a Policy from CLI flags.
func New(failOn string, ignoreIDs []string) *Policy {
	ignore := make(map[string]bool, len(ignoreIDs))
	for _, id := range ignoreIDs {
		ignore[normID(id)] = true
	}
	return &Policy{
		FailOn:    model.ParseSeverity(failOn),
		IgnoreIDs: ignore,
	}
}

// Filter removes ignored findings and returns only actionable ones.
func (p *Policy) Filter(findings []model.Finding, components []model.Component) []model.Finding {
	var filtered []model.Finding
	for _, f := range findings {
		if p.IgnoreIDs[normID(f.VulnID)] {
			continue
		}
		ignored := false
		for _, alias := range f.Aliases {
			if p.IgnoreIDs[normID(alias)] {
				ignored = true
				break
			}
		}
		if ignored || vexSuppressed(p.VEXStatements, f, components) {
			continue
		}
		filtered = append(filtered, f)
	}
	return filtered
}

func vexSuppressed(statements map[string][]VEXStatement, f model.Finding, components []model.Component) bool {
	if len(statements) == 0 {
		return false
	}

	if primary, ok := statements[normID(f.VulnID)]; ok {
		return statementsSuppress(primary, f, components)
	}
	for _, alias := range f.Aliases {
		if aliasStatements, ok := statements[normID(alias)]; ok && statementsSuppress(aliasStatements, f, components) {
			return true
		}
	}
	return false
}

func statementsSuppress(statements []VEXStatement, f model.Finding, components []model.Component) bool {
	for _, statement := range statements {
		if statement.Status != "not_affected" && statement.Status != "fixed" {
			continue
		}
		for _, product := range statement.Products {
			if productMatches(product, f, components) {
				return true
			}
		}
	}
	return false
}

func productMatches(product string, f model.Finding, components []model.Component) bool {
	if product == f.ComponentRef {
		return true
	}
	for _, component := range components {
		if component.Name+"@"+component.Version != f.ComponentRef {
			continue
		}
		if product == component.PURL || product == component.CPE {
			return true
		}
	}
	return false
}

// ExitCode determines the process exit code based on findings.
func (p *Policy) ExitCode(findings []model.Finding) model.ExitCode {
	if p.FailOn == model.SeverityNone {
		return model.ExitOK
	}
	for _, f := range findings {
		if model.ParseSeverity(f.Severity) >= p.FailOn {
			return model.ExitFindings
		}
	}
	return model.ExitOK
}
