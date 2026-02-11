package report

import (
	"encoding/json"
	"fmt"
	"io"
)

// SARIFReporter writes output in SARIF 2.1.0 format.
type SARIFReporter struct{}

type sarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version"`
	InformationURI string      `json:"informationUri"`
	Rules          []sarifRule `json:"rules,omitempty"`
}

type sarifRule struct {
	ID               string          `json:"id"`
	ShortDescription sarifMessage    `json:"shortDescription"`
	DefaultConfig    sarifRuleConfig `json:"defaultConfiguration"`
}

type sarifRuleConfig struct {
	Level string `json:"level"`
}

type sarifResult struct {
	RuleID    string          `json:"ruleId"`
	Level     string          `json:"level"`
	Message   sarifMessage    `json:"message"`
	Locations []sarifLocation `json:"locations"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysicalLocation `json:"physicalLocation"`
}

type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifactLocation `json:"artifactLocation"`
}

type sarifArtifactLocation struct {
	URI string `json:"uri"`
}

type sarifMessage struct {
	Text string `json:"text"`
}

func (r *SARIFReporter) Write(w io.Writer, data any) error {
	raw, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("encoding SARIF: %w", err)
	}

	var scanOutput struct {
		Target   string `json:"target"`
		Findings []struct {
			VulnID       string `json:"vulnID"`
			Severity     string `json:"severity"`
			ComponentRef string `json:"componentRef"`
		} `json:"findings"`
	}

	log := sarifLog{
		Schema:  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
		Version: "2.1.0",
		Runs: []sarifRun{
			{
				Tool: sarifTool{
					Driver: sarifDriver{
						Name:           "vulners",
						Version:        Version,
						InformationURI: "https://github.com/kidoz/vulners-cli",
					},
				},
				Results: []sarifResult{},
			},
		},
	}

	if err := json.Unmarshal(raw, &scanOutput); err != nil {
		return fmt.Errorf("parsing scan output for SARIF: %w", err)
	}

	target := scanOutput.Target
	if target == "" {
		target = "."
	}

	seenRules := make(map[string]bool)
	for _, f := range scanOutput.Findings {
		if !seenRules[f.VulnID] {
			seenRules[f.VulnID] = true
			log.Runs[0].Tool.Driver.Rules = append(log.Runs[0].Tool.Driver.Rules, sarifRule{
				ID:               f.VulnID,
				ShortDescription: sarifMessage{Text: f.VulnID},
				DefaultConfig:    sarifRuleConfig{Level: sarifLevel(f.Severity)},
			})
		}

		log.Runs[0].Results = append(log.Runs[0].Results, sarifResult{
			RuleID:  f.VulnID,
			Level:   sarifLevel(f.Severity),
			Message: sarifMessage{Text: fmt.Sprintf("%s in %s", f.VulnID, f.ComponentRef)},
			Locations: []sarifLocation{
				{PhysicalLocation: sarifPhysicalLocation{
					ArtifactLocation: sarifArtifactLocation{URI: target},
				}},
			},
		})
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(log); err != nil {
		return fmt.Errorf("encoding SARIF: %w", err)
	}
	return nil
}

func sarifLevel(severity string) string {
	switch severity {
	case "critical", "high":
		return "error"
	case "medium":
		return "warning"
	default:
		return "note"
	}
}
