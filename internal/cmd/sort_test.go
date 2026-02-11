package cmd

import (
	"testing"

	"github.com/kidoz/vulners-cli/internal/model"
	"github.com/stretchr/testify/assert"
)

func TestSortFindings_BySeverityDescThenVulnIDAsc(t *testing.T) {
	findings := []model.Finding{
		{VulnID: "CVE-2023-0002", Severity: "low"},
		{VulnID: "CVE-2023-0001", Severity: "critical"},
		{VulnID: "CVE-2023-0004", Severity: "high"},
		{VulnID: "CVE-2023-0003", Severity: "critical"},
		{VulnID: "CVE-2023-0005", Severity: "medium"},
	}

	sortFindings(findings)

	want := []string{
		"CVE-2023-0001", // critical (alpha first)
		"CVE-2023-0003", // critical
		"CVE-2023-0004", // high
		"CVE-2023-0005", // medium
		"CVE-2023-0002", // low
	}
	got := make([]string, len(findings))
	for i, f := range findings {
		got[i] = f.VulnID
	}
	assert.Equal(t, want, got)
}

func TestSortFindings_Empty(t *testing.T) {
	var findings []model.Finding
	sortFindings(findings) // should not panic
	assert.Empty(t, findings)
}

func TestSortFindings_Deterministic(t *testing.T) {
	make := func() []model.Finding {
		return []model.Finding{
			{VulnID: "CVE-B", Severity: "high"},
			{VulnID: "CVE-A", Severity: "high"},
			{VulnID: "CVE-C", Severity: "high"},
		}
	}
	a := make()
	b := make()
	sortFindings(a)
	sortFindings(b)

	for i := range a {
		assert.Equal(t, a[i].VulnID, b[i].VulnID, "sort must be deterministic at index %d", i)
	}
}
