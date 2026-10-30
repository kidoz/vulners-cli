package policy

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/kidoz/vulners-cli/internal/model"
)

func TestPolicy_Filter(t *testing.T) {
	p := New("", []string{"CVE-2021-44228", "CVE-2023-0001"})
	findings := []model.Finding{
		{VulnID: "CVE-2021-44228", Severity: "critical"},
		{VulnID: "CVE-2023-0002", Severity: "high"},
		{VulnID: "CVE-2023-0003", Severity: "low", Aliases: []string{"CVE-2023-0001"}},
		{VulnID: "CVE-2023-0004", Severity: "medium"},
	}

	filtered := p.Filter(findings, nil)
	assert.Len(t, filtered, 2)
	assert.Equal(t, "CVE-2023-0002", filtered[0].VulnID)
	assert.Equal(t, "CVE-2023-0004", filtered[1].VulnID)
}

func TestPolicy_Filter_CaseInsensitive(t *testing.T) {
	p := New("", []string{"cve-2021-44228", "cve-2023-0001"})
	findings := []model.Finding{
		{VulnID: "CVE-2021-44228", Severity: "critical"},
		{VulnID: "cve-2023-0003", Severity: "low", Aliases: []string{"CVE-2023-0001"}},
		{VulnID: "CVE-2023-0002", Severity: "high"},
	}

	filtered := p.Filter(findings, nil)
	assert.Len(t, filtered, 1)
	assert.Equal(t, "CVE-2023-0002", filtered[0].VulnID)
}

func TestPolicy_Filter_VEXCaseInsensitive(t *testing.T) {
	p := New("", nil)
	p.VEXStatements = map[string][]VEXStatement{
		"CVE-2021-44228": {{Status: "not_affected", Products: []string{"pkg@1.0"}}},
	}
	findings := []model.Finding{
		{VulnID: "cve-2021-44228", Severity: "critical", ComponentRef: "pkg@1.0"},
		{VulnID: "CVE-2023-0002", Severity: "high", ComponentRef: "pkg@1.0"},
	}

	filtered := p.Filter(findings, nil)
	assert.Len(t, filtered, 1)
	assert.Equal(t, "CVE-2023-0002", filtered[0].VulnID)
}

func TestPolicy_ExitCode_Reachability(t *testing.T) {
	p := New("high", nil)

	imported := []model.Finding{
		{VulnID: "GO-2024-0001", Severity: "critical", Reachability: "imported"},
	}
	assert.Equal(t, model.ExitOK, p.ExitCode(imported), "imported findings must not fail the build")

	imported[0].Reachability = "reachable"
	assert.Equal(t, model.ExitFindings, p.ExitCode(imported), "reachable findings must fail the build")

	imported[0].Reachability = ""
	assert.Equal(t, model.ExitFindings, p.ExitCode(imported), "findings without reachability data must fail the build")
}

func TestPolicy_ExitCode(t *testing.T) {
	tests := []struct {
		name     string
		failOn   string
		findings []model.Finding
		want     model.ExitCode
	}{
		{name: "no fail-on", failOn: "", findings: []model.Finding{{Severity: "critical"}}, want: model.ExitOK},
		{name: "fail-on high has critical", failOn: "high", findings: []model.Finding{{Severity: "critical"}}, want: model.ExitFindings},
		{name: "fail-on high only medium", failOn: "high", findings: []model.Finding{{Severity: "medium"}}, want: model.ExitOK},
		{name: "fail-on critical has high", failOn: "critical", findings: []model.Finding{{Severity: "high"}}, want: model.ExitOK},
		{name: "no findings", failOn: "low", findings: nil, want: model.ExitOK},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := New(tt.failOn, nil)
			assert.Equal(t, tt.want, p.ExitCode(tt.findings))
		})
	}
}
