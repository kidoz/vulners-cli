package intel

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"

	"golang.org/x/vuln/scan"

	"github.com/kidoz/vulners-cli/internal/model"
)

// govulncheckFinding represents a single finding from govulncheck JSON output.
type govulncheckFinding struct {
	OSV          string `json:"osv"`
	FixedVersion string `json:"fixedVersion"`
	Trace        []struct {
		Module   string `json:"module"`
		Version  string `json:"version"`
		Package  string `json:"package"`
		Function string `json:"function"`
	} `json:"trace"`
}

// govulncheckMessage is a wrapper for the JSON streaming output.
type govulncheckMessage struct {
	Finding *govulncheckFinding `json:"finding,omitempty"`
}

// RunGovulncheck runs govulncheck on a Go module directory and returns findings.
func RunGovulncheck(ctx context.Context, dir string, logger *slog.Logger) ([]model.Finding, error) {
	logger.Debug("running govulncheck", "dir", dir)

	var stdout, stderr bytes.Buffer
	cmd := scan.Command(ctx, "-json", "-C", dir, "./...")
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("starting govulncheck: %w", err)
	}
	waitErr := cmd.Wait()
	if waitErr != nil {
		// govulncheck exits non-zero when vulns are found; that's expected.
		// But if stdout is empty, this is a real failure (e.g. killed, bad args).
		logger.Debug("govulncheck finished", "exit_error", waitErr, "stderr", stderr.String())
		if stdout.Len() == 0 {
			return nil, fmt.Errorf("govulncheck failed: %w: %s", waitErr, stderr.String())
		}
	}

	return parseGovulncheckOutput(stdout.Bytes(), logger)
}

func parseGovulncheckOutput(data []byte, logger *slog.Logger) ([]model.Finding, error) {
	var findings []model.Finding
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

		f := model.Finding{
			VulnID:       msg.Finding.OSV,
			Severity:     "unknown",
			Reachability: reachability(msg.Finding),
		}

		if msg.Finding.FixedVersion != "" {
			f.Fix = msg.Finding.FixedVersion
		}

		if len(msg.Finding.Trace) > 0 {
			trace := msg.Finding.Trace[0]
			f.ComponentRef = trace.Module + "@" + trace.Version
		}

		findings = append(findings, f)
	}

	return findings, nil
}

func reachability(f *govulncheckFinding) string {
	for _, t := range f.Trace {
		if t.Function != "" {
			return "reachable"
		}
	}
	return "imported"
}
