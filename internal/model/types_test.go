package model

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseSeverity(t *testing.T) {
	tests := []struct {
		input string
		want  SeverityLevel
	}{
		{"critical", SeverityCritical},
		{"high", SeverityHigh},
		{"medium", SeverityMedium},
		{"low", SeverityLow},
		{"none", SeverityNone},
		{"", SeverityNone},
		{"unknown", SeverityNone},
		{"Critical", SeverityCritical},
		{"HIGH", SeverityHigh},
		{"Medium", SeverityMedium},
		{"LOW", SeverityLow},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			assert.Equal(t, tt.want, ParseSeverity(tt.input))
		})
	}
}

func TestSeverityLevel_String(t *testing.T) {
	tests := []struct {
		level SeverityLevel
		want  string
	}{
		{SeverityCritical, "critical"},
		{SeverityHigh, "high"},
		{SeverityMedium, "medium"},
		{SeverityLow, "low"},
		{SeverityNone, "none"},
	}
	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			assert.Equal(t, tt.want, tt.level.String())
		})
	}
}

func TestExitCodes(t *testing.T) {
	assert.Equal(t, ExitCode(0), ExitOK)
	assert.Equal(t, ExitCode(1), ExitFindings)
	assert.Equal(t, ExitCode(2), ExitUsageError)
	assert.Equal(t, ExitCode(3), ExitRuntimeError)
}

func TestExitError(t *testing.T) {
	err := &ExitError{Code: ExitFindings}
	assert.Equal(t, "exit code 1", err.Error())
	assert.Equal(t, ExitFindings, err.Code)
}

func TestFinding_JSONSerialization(t *testing.T) {
	score := 0.85
	aiScore := 7.5
	f := Finding{
		VulnID:        "CVE-2021-44228",
		Severity:      "critical",
		CVSS:          10.0,
		EPSS:          &score,
		AIScore:       &aiScore,
		HasExploit:    true,
		WildExploited: true,
		ComponentRef:  "log4j@2.14.0",
	}

	data, err := json.Marshal(f)
	assert.NoError(t, err)

	var decoded Finding
	err = json.Unmarshal(data, &decoded)
	assert.NoError(t, err)

	assert.Equal(t, f.VulnID, decoded.VulnID)
	assert.NotNil(t, decoded.EPSS)
	assert.Equal(t, 0.85, *decoded.EPSS)
	assert.NotNil(t, decoded.AIScore)
	assert.Equal(t, 7.5, *decoded.AIScore)
	assert.True(t, decoded.WildExploited)
	assert.True(t, decoded.HasExploit)
}

func TestFinding_JSON_OmitsEmpty(t *testing.T) {
	f := Finding{
		VulnID:       "CVE-2023-0001",
		Severity:     "low",
		ComponentRef: "pkg@1.0",
	}

	data, err := json.Marshal(f)
	assert.NoError(t, err)

	s := string(data)
	assert.NotContains(t, s, "aiScore")
	assert.NotContains(t, s, "wildExploited")
	assert.NotContains(t, s, "epss")
}

func TestScoreSeverity(t *testing.T) {
	tests := []struct {
		score float64
		want  string
	}{
		{9.5, "critical"},
		{9.0, "critical"},
		{8.0, "high"},
		{7.0, "high"},
		{5.0, "medium"},
		{4.0, "medium"},
		{2.0, "low"},
		{0.1, "low"},
		{0, "none"},
	}
	for _, tt := range tests {
		assert.Equal(t, tt.want, ScoreSeverity(tt.score), "score=%v", tt.score)
	}
}
