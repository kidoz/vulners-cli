package cmd

import (
	"sort"

	"github.com/kidoz/vulners-cli/internal/model"
)

// sortFindings sorts findings deterministically: severity descending (critical
// first), then VulnID ascending. Used in --agent mode for stable output.
func sortFindings(findings []model.Finding) {
	sort.Slice(findings, func(i, j int) bool {
		si := model.ParseSeverity(findings[i].Severity)
		sj := model.ParseSeverity(findings[j].Severity)
		if si != sj {
			return si > sj // higher severity first
		}
		return findings[i].VulnID < findings[j].VulnID
	})
}

// topNFindings returns the top n findings by severity (desc) then CVSS (desc).
// The input slice is not modified.
func topNFindings(findings []model.Finding, n int) []model.Finding {
	if len(findings) == 0 {
		return nil
	}
	sorted := make([]model.Finding, len(findings))
	copy(sorted, findings)
	sortFindings(sorted)
	if n > len(sorted) {
		n = len(sorted)
	}
	return sorted[:n]
}
