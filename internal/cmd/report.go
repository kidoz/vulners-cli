package cmd

import (
	"context"
	"fmt"
)

// ReportCmd is the parent command for account-level reports.
type ReportCmd struct {
	Summary ReportSummaryCmd `cmd:"" help:"Aggregated vulnerability summary"`
	Vulns   ReportVulnsCmd   `cmd:"" help:"List known vulnerabilities"`
	Hosts   ReportHostsCmd   `cmd:"" help:"Host vulnerability status"`
	Scans   ReportScansCmd   `cmd:"" help:"Scan history"`
	IPs     ReportIPsCmd     `cmd:"" name:"ips" help:"IP-level vulnerability summary"`
}

// ReportSummaryCmd returns an aggregated vulnerability summary.
type ReportSummaryCmd struct {
	Limit  int `help:"Maximum results" default:"100"`
	Offset int `help:"Result offset" default:"0"`
}

func (c *ReportSummaryCmd) Run(ctx context.Context, globals *CLI, deps *Deps) error {
	if err := validateNonScanFormat(globals.Output); err != nil {
		return err
	}
	if globals.Offline {
		return fmt.Errorf("report commands do not support offline mode")
	}
	if deps.Intel == nil {
		return fmt.Errorf("VULNERS_API_KEY is required for report commands")
	}

	result, err := deps.Intel.VulnsSummaryReport(ctx, c.Limit, c.Offset)
	if err != nil {
		return fmt.Errorf("report summary failed: %w", err)
	}

	w, closer, werr := outputWriter(globals)
	if werr != nil {
		return werr
	}
	defer func() { _ = closer() }()

	return writeIntelOutput(w, globals, "report summary", result, nil)
}

// ReportVulnsCmd lists known vulnerabilities.
type ReportVulnsCmd struct {
	Limit  int `help:"Maximum results" default:"100"`
	Offset int `help:"Result offset" default:"0"`
}

func (c *ReportVulnsCmd) Run(ctx context.Context, globals *CLI, deps *Deps) error {
	if err := validateNonScanFormat(globals.Output); err != nil {
		return err
	}
	if globals.Offline {
		return fmt.Errorf("report commands do not support offline mode")
	}
	if deps.Intel == nil {
		return fmt.Errorf("VULNERS_API_KEY is required for report commands")
	}

	result, err := deps.Intel.VulnsList(ctx, c.Limit, c.Offset)
	if err != nil {
		return fmt.Errorf("report vulns failed: %w", err)
	}

	w, closer, werr := outputWriter(globals)
	if werr != nil {
		return werr
	}
	defer func() { _ = closer() }()

	return writeIntelOutput(w, globals, "report vulns", result, nil)
}

// ReportHostsCmd returns host vulnerability status.
type ReportHostsCmd struct {
	Limit  int `help:"Maximum results" default:"100"`
	Offset int `help:"Result offset" default:"0"`
}

func (c *ReportHostsCmd) Run(ctx context.Context, globals *CLI, deps *Deps) error {
	if err := validateNonScanFormat(globals.Output); err != nil {
		return err
	}
	if globals.Offline {
		return fmt.Errorf("report commands do not support offline mode")
	}
	if deps.Intel == nil {
		return fmt.Errorf("VULNERS_API_KEY is required for report commands")
	}

	result, err := deps.Intel.HostVulns(ctx, c.Limit, c.Offset)
	if err != nil {
		return fmt.Errorf("report hosts failed: %w", err)
	}

	w, closer, werr := outputWriter(globals)
	if werr != nil {
		return werr
	}
	defer func() { _ = closer() }()

	return writeIntelOutput(w, globals, "report hosts", result, nil)
}

// ReportScansCmd lists scan history.
type ReportScansCmd struct {
	Limit  int `help:"Maximum results" default:"100"`
	Offset int `help:"Result offset" default:"0"`
}

func (c *ReportScansCmd) Run(ctx context.Context, globals *CLI, deps *Deps) error {
	if err := validateNonScanFormat(globals.Output); err != nil {
		return err
	}
	if globals.Offline {
		return fmt.Errorf("report commands do not support offline mode")
	}
	if deps.Intel == nil {
		return fmt.Errorf("VULNERS_API_KEY is required for report commands")
	}

	result, err := deps.Intel.ScanList(ctx, c.Limit, c.Offset)
	if err != nil {
		return fmt.Errorf("report scans failed: %w", err)
	}

	w, closer, werr := outputWriter(globals)
	if werr != nil {
		return werr
	}
	defer func() { _ = closer() }()

	return writeIntelOutput(w, globals, "report scans", result, nil)
}

// ReportIPsCmd returns IP-level vulnerability summary.
type ReportIPsCmd struct{}

func (c *ReportIPsCmd) Run(ctx context.Context, globals *CLI, deps *Deps) error {
	if err := validateNonScanFormat(globals.Output); err != nil {
		return err
	}
	if globals.Offline {
		return fmt.Errorf("report commands do not support offline mode")
	}
	if deps.Intel == nil {
		return fmt.Errorf("VULNERS_API_KEY is required for report commands")
	}

	result, err := deps.Intel.IPSummaryReport(ctx)
	if err != nil {
		return fmt.Errorf("report ips failed: %w", err)
	}

	w, closer, werr := outputWriter(globals)
	if werr != nil {
		return werr
	}
	defer func() { _ = closer() }()

	return writeIntelOutput(w, globals, "report ips", result, nil)
}
