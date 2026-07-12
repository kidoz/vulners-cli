package cmd

import (
	"context"
	"fmt"

	vulners "github.com/kidoz/go-vulners"
)

// ScanWebCmd checks web application paths against known vulnerabilities.
type ScanWebCmd struct {
	Path            []string `help:"Web path to check (repeatable), e.g. /wp-login.php" required:""`
	Software        string   `help:"Application product name to scope matching (optional)" default:""`
	SoftwareVersion string   `help:"Application version to scope matching (optional)" default:""`
}

// WebScanOutput wraps web vulnerability results keyed by path.
type WebScanOutput struct {
	Results map[string][]vulners.WebVulnerability `json:"results"`
}

// Run executes the 'scan web' command.
func (c *ScanWebCmd) Run(ctx context.Context, globals *CLI, deps *Deps) error {
	if err := validateNonScanFormat(globals.Output); err != nil {
		return err
	}
	if globals.Offline {
		return fmt.Errorf("web scanning does not support offline mode")
	}
	if deps.Intel == nil {
		return fmt.Errorf("VULNERS_API_KEY is required for web scanning")
	}
	if len(c.Path) == 0 {
		return fmt.Errorf("no paths provided for web scanning")
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

	w, closer, werr := outputWriter(globals)
	if werr != nil {
		return werr
	}
	defer func() { _ = closer() }()

	return writeIntelOutput(w, globals, "scan web", WebScanOutput{Results: results}, nil)
}
