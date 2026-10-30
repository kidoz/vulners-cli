package intel

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"

	"github.com/kidoz/vulners-cli/internal/boundedio"

	"golang.org/x/vuln/scan"

	"github.com/kidoz/vulners-cli/internal/model"
)

// govulncheckFinding represents a single finding from govulncheck JSON output.
type govulncheckFinding struct {
	OSV          string `json:"osv"`
	FixedVersion string `json:"fixed_version"`
	Trace        []struct {
		Module   string `json:"module"`
		Version  string `json:"version"`
		Package  string `json:"package"`
		Function string `json:"function"`
	} `json:"trace"`
}

// govulncheckOSV carries the advisory metadata govulncheck emits in the stream.
type govulncheckOSV struct {
	ID      string   `json:"id"`
	Aliases []string `json:"aliases"`
}

// govulncheckMessage is a wrapper for the JSON streaming output.
type govulncheckMessage struct {
	Finding *govulncheckFinding `json:"finding,omitempty"`
	OSV     *govulncheckOSV     `json:"osv,omitempty"`
}

// RunGovulncheck runs govulncheck on a Go module directory and returns findings.
func RunGovulncheck(ctx context.Context, dir string, logger *slog.Logger) ([]model.Finding, error) {
	logger.Debug("running govulncheck", "dir", dir)

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	stdout := boundedio.NewBuffer(boundedio.StdoutLimit, cancel)
	stderr := boundedio.NewBuffer(boundedio.StderrLimit, cancel)
	cmd := scan.Command(ctx, "-json", "-C", dir, "./...")
	cmd.Stdout = stdout
	cmd.Stderr = stderr

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("starting govulncheck: %w", err)
	}
	err := cmd.Wait()
	if limitErr := errors.Join(stdout.Err(), stderr.Err()); limitErr != nil {
		return nil, limitErr
	}
	if err != nil {
		logger.Debug("govulncheck finished", "exit_error", err, "stderr", stderr.String())
		return nil, fmt.Errorf("govulncheck failed: %w: %s", err, stderr.String())
	}

	return parseGovulncheckOutput(stdout.Bytes(), logger)
}

func parseGovulncheckOutput(data []byte, logger *slog.Logger) ([]model.Finding, error) {
	aliases, err := parseGovulncheckAliases(data, logger)
	if err != nil {
		return nil, err
	}

	var findings []model.Finding
	byComponent := make(map[string]int)
	decoder := json.NewDecoder(bytes.NewReader(data))

	for decoder.More() {
		var msg govulncheckMessage
		if err := decoder.Decode(&msg); err != nil {
			logger.Warn("govulncheck output may be truncated", "error", err, "parsed_so_far", len(findings))
			return findings, fmt.Errorf("incomplete govulncheck output (parsed %d findings): %w", len(findings), err)
		}

		if msg.Finding == nil {
			continue
		}

		f := findingFromGovulncheck(msg.Finding, aliases[msg.Finding.OSV])
		key := f.VulnID + "\x00" + f.ComponentRef
		if i, ok := byComponent[key]; ok {
			mergeFinding(&findings[i], f)
			continue
		}
		byComponent[key] = len(findings)
		findings = append(findings, f)
	}

	return findings, nil
}

// parseGovulncheckAliases collects OSV advisory aliases. govulncheck emits OSV
// messages in the same stream as findings, so a separate pass keeps the parser
// independent of message ordering.
func parseGovulncheckAliases(data []byte, logger *slog.Logger) (map[string][]string, error) {
	aliases := make(map[string][]string)
	decoder := json.NewDecoder(bytes.NewReader(data))

	for decoder.More() {
		var msg govulncheckMessage
		if err := decoder.Decode(&msg); err != nil {
			logger.Warn("govulncheck output may be truncated", "error", err)
			return nil, fmt.Errorf("incomplete govulncheck output: %w", err)
		}
		if msg.OSV != nil && msg.OSV.ID != "" {
			aliases[msg.OSV.ID] = msg.OSV.Aliases
		}
	}

	return aliases, nil
}

func findingFromGovulncheck(g *govulncheckFinding, aliases []string) model.Finding {
	f := model.Finding{
		VulnID:       g.OSV,
		Aliases:      aliases,
		Severity:     "unknown",
		Reachability: reachability(g),
		Fix:          g.FixedVersion,
	}
	if len(g.Trace) > 0 {
		trace := g.Trace[0]
		f.ComponentRef = trace.Module + "@" + trace.Version
	}
	return f
}

// mergeFinding combines duplicate govulncheck findings for the same advisory
// and module, keeping the strongest reachability signal and any fixed version.
func mergeFinding(dst *model.Finding, src model.Finding) {
	if dst.Reachability != "reachable" && src.Reachability == "reachable" {
		dst.Reachability = src.Reachability
	}
	if dst.Fix == "" {
		dst.Fix = src.Fix
	}
	if len(dst.Aliases) == 0 {
		dst.Aliases = src.Aliases
	}
}

func reachability(f *govulncheckFinding) string {
	for _, t := range f.Trace {
		if t.Function != "" {
			return "reachable"
		}
	}
	return "imported"
}
