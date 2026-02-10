package policy

import (
	"github.com/kidoz/vulners-cli/internal/model"
)

// Policy determines which findings matter and what exit code to return.
type Policy struct {
	FailOn      model.SeverityLevel
	IgnoreIDs   map[string]bool
	VEXStatuses map[string]string
}

// New creates a Policy from CLI flags.
func New(failOn string, ignoreIDs []string) *Policy {
	ignore := make(map[string]bool, len(ignoreIDs))
	for _, id := range ignoreIDs {
		ignore[id] = true
	}
	return &Policy{
		FailOn:    model.ParseSeverity(failOn),
		IgnoreIDs: ignore,
	}
}

// Filter removes ignored findings and returns only actionable ones.
func (p *Policy) Filter(findings []model.Finding) []model.Finding {
	var filtered []model.Finding
	for _, f := range findings {
		if p.IgnoreIDs[f.VulnID] {
			continue
		}
		// Also check aliases.
		ignored := false
		for _, alias := range f.Aliases {
			if p.IgnoreIDs[alias] {
				ignored = true
				break
			}
		}
		if ignored {
			continue
		}
		// Check VEX status — suppress "not_affected" and "fixed".
		if vexSuppressed(p.VEXStatuses, f) {
			continue
		}
		filtered = append(filtered, f)
	}
	return filtered
}

func vexSuppressed(statuses map[string]string, f model.Finding) bool {
	if len(statuses) == 0 {
		return false
	}
	// Check VulnID and all aliases.
	ids := append([]string{f.VulnID}, f.Aliases...)
	for _, id := range ids {
		if status, ok := statuses[id]; ok {
			if status == "not_affected" || status == "fixed" {
				return true
			}
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
