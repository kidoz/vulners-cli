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

	filtered := p.Filter(findings)
	assert.Len(t, filtered, 2)
	assert.Equal(t, "CVE-2023-0002", filtered[0].VulnID)
	assert.Equal(t, "CVE-2023-0004", filtered[1].VulnID)
}

func TestPolicy_ExitCode(t *testing.T) {
	tests := []struct {
		name     string
		failOn   string
		findings []model.Finding
		want     model.ExitCode
	}{
		{
			name:   "no fail-on, always OK",
			failOn: "",
			findings: []model.Finding{
				{Severity: "critical"},
			},
			want: model.ExitOK,
		},
		{
			name:   "fail-on high, has critical",
			failOn: "high",
			findings: []model.Finding{
				{Severity: "critical"},
			},
			want: model.ExitFindings,
		},
		{
			name:   "fail-on high, only medium",
			failOn: "high",
			findings: []model.Finding{
				{Severity: "medium"},
			},
			want: model.ExitOK,
		},
		{
			name:   "fail-on critical, has high",
			failOn: "critical",
			findings: []model.Finding{
				{Severity: "high"},
			},
			want: model.ExitOK,
		},
		{
			name:     "no findings",
			failOn:   "low",
			findings: nil,
			want:     model.ExitOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := New(tt.failOn, nil)
			assert.Equal(t, tt.want, p.ExitCode(tt.findings))
		})
	}
}
