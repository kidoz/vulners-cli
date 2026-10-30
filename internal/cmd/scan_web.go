package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	vulners "github.com/kidoz/go-vulners"
	"github.com/kidoz/vulners-cli/internal/model"
)

// ScanWebCmd checks web application paths against known vulnerabilities.
type ScanWebCmd struct {
	Path            []string `help:"Web path to check (repeatable), e.g. /wp-login.php" required:""`
	Software        string   `help:"Application product name to scope matching (optional)" default:""`
	SoftwareVersion string   `help:"Application version to scope matching (optional)" default:""`
}

func (c *ScanWebCmd) Run(ctx context.Context, globals *CLI, deps *Deps) error {
	if globals.Offline {
		return fmt.Errorf("web scanning does not support offline mode")
	}
	if len(c.Path) == 0 {
		return fmt.Errorf("no paths provided for web scanning")
	}
	target := strings.Join(c.Path, ",")
	components := c.components()
	if globals.Plan {
		return writeScanPlan(globals, PlanOutput{Target: target, Mode: "online", ComponentCount: len(components), HasAPIKey: deps.Intel != nil, Components: components, Steps: []string{"look up web paths", "apply policy and report"}})
	}
	if deps.Intel == nil {
		return usageErrorf("VULNERS_API_KEY is required for web scanning")
	}
	if _, err := newPolicy(globals); err != nil {
		return err
	}
	var application any
	if c.Software != "" {
		app := map[string]string{"product": c.Software}
		if c.SoftwareVersion != "" {
			app["version"] = c.SoftwareVersion
		}
		application = app
	}
	results, err := deps.Intel.GetWebVulnerabilities(ctx, c.Path, application)
	if err != nil {
		return fmt.Errorf("web scanning failed: %w", err)
	}
	return finalizeScan(globals, target, components, c.findings(results))
}

func (c *ScanWebCmd) components() []model.Component {
	if c.Software != "" {
		return []model.Component{{Type: "web", Name: c.Software, Version: c.SoftwareVersion, Locations: c.Path}}
	}
	components := make([]model.Component, 0, len(c.Path))
	for _, path := range c.Path {
		components = append(components, model.Component{Type: "web", Name: path, Locations: []string{path}})
	}
	return components
}

func (c *ScanWebCmd) findings(results map[string][]vulners.WebVulnerability) []model.Finding {
	paths := make([]string, 0, len(results))
	for path := range results {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	var findings []model.Finding
	for _, path := range paths {
		ref := path + "@"
		if c.Software != "" {
			ref = c.Software + "@" + c.SoftwareVersion
		}
		for _, v := range results[path] {
			score, severity := webSeverity(v.Metrics)
			findings = append(findings, model.Finding{VulnID: v.ID, ComponentRef: ref, CVSS: score, Severity: severity, HasExploit: len(v.Exploits) > 0 || v.Type == "exploit", References: []string{path}})
		}
	}
	return findings
}

// Prefer the newest CVSS generation, taking the highest score across providers.
// Provider iteration order must not affect policy decisions.
func webSeverity(metrics map[string]any) (float64, string) {
	for _, keys := range [][]string{{"cvss4", "cvss40"}, {"cvss3", "cvss31", "cvss30"}, {"cvss", "cvss2"}} {
		score := webProviderScore(metrics, keys)
		for _, value := range metrics {
			if provider, ok := value.(map[string]any); ok {
				score = max(score, webProviderScore(provider, keys))
			}
		}
		if score > 0 {
			return score, model.ScoreSeverity(score)
		}
	}
	return 0, "unknown"
}

func webProviderScore(metrics map[string]any, keys []string) float64 {
	var best float64
	for _, key := range keys {
		raw, err := json.Marshal(metrics[key])
		if err != nil {
			continue
		}
		var score float64
		if json.Unmarshal(raw, &score) != nil {
			var cvss struct {
				Score     float64 `json:"score"`
				BaseScore float64 `json:"baseScore"`
			}
			if json.Unmarshal(raw, &cvss) != nil {
				continue
			}
			score = max(cvss.Score, cvss.BaseScore)
		}
		if score > 0 && score <= 10 {
			best = max(best, score)
		}
	}
	return best
}
