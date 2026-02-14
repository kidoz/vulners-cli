package model

import (
	"fmt"
	"strings"
)

// OutputFormat specifies the output format for command results.
type OutputFormat string

const (
	OutputJSON      OutputFormat = "json"
	OutputTable     OutputFormat = "table"
	OutputSARIF     OutputFormat = "sarif"
	OutputHTML      OutputFormat = "html"
	OutputCycloneDX OutputFormat = "cyclonedx"
	OutputMarkdown  OutputFormat = "markdown"
)

// ExitCode represents the process exit code.
type ExitCode int

const (
	ExitOK           ExitCode = 0 // No findings above threshold
	ExitFindings     ExitCode = 1 // Findings above threshold
	ExitUsageError   ExitCode = 2 // Usage or configuration error
	ExitRuntimeError ExitCode = 3 // Runtime error (API failure, etc.)
)

// Component represents a software component in the inventory.
type Component struct {
	Type      string   `json:"type"`
	Name      string   `json:"name"`
	Version   string   `json:"version"`
	PURL      string   `json:"purl,omitempty"`
	CPE       string   `json:"cpe,omitempty"`
	Locations []string `json:"locations,omitempty"`
	Ecosystem string   `json:"ecosystem,omitempty"` // "apk", "deb", "rpm", "npm", "go", etc.
}

// Finding represents a vulnerability finding for a component.
type Finding struct {
	VulnID        string   `json:"vulnID"`
	Aliases       []string `json:"aliases,omitempty"`
	Severity      string   `json:"severity"`
	CVSS          float64  `json:"cvss,omitempty"`
	EPSS          *float64 `json:"epss,omitempty"`
	AIScore       *float64 `json:"aiScore,omitempty"`
	HasExploit    bool     `json:"hasExploit,omitempty"`
	WildExploited bool     `json:"wildExploited,omitempty"`
	ComponentRef  string   `json:"componentRef"`
	Fix           string   `json:"fix,omitempty"`
	References    []string `json:"references,omitempty"`
	Reachability  string   `json:"reachability,omitempty"`
}

// SeverityLevel represents vulnerability severity for policy filtering.
type SeverityLevel int

const (
	SeverityNone SeverityLevel = iota
	SeverityLow
	SeverityMedium
	SeverityHigh
	SeverityCritical
)

// ExitError wraps an ExitCode so commands can signal a non-zero exit
// without calling os.Exit directly.
type ExitError struct {
	Code ExitCode
}

func (e *ExitError) Error() string {
	return fmt.Sprintf("exit code %d", int(e.Code))
}

// ParseSeverity converts a severity string to SeverityLevel (case-insensitive).
func ParseSeverity(s string) SeverityLevel {
	switch strings.ToLower(s) {
	case "critical":
		return SeverityCritical
	case "high":
		return SeverityHigh
	case "medium":
		return SeverityMedium
	case "low":
		return SeverityLow
	default:
		return SeverityNone
	}
}

// ScoreSeverity maps a CVSS score to a severity label.
func ScoreSeverity(score float64) string {
	switch {
	case score >= 9.0:
		return "critical"
	case score >= 7.0:
		return "high"
	case score >= 4.0:
		return "medium"
	case score > 0:
		return "low"
	default:
		return "none"
	}
}

// String returns the string representation of a SeverityLevel.
func (s SeverityLevel) String() string {
	switch s {
	case SeverityCritical:
		return "critical"
	case SeverityHigh:
		return "high"
	case SeverityMedium:
		return "medium"
	case SeverityLow:
		return "low"
	default:
		return "none"
	}
}
