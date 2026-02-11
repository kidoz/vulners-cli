package cmd

import (
	"context"
	"fmt"
)

// LinuxAuditCmd audits Linux distribution packages.
type LinuxAuditCmd struct {
	Distro  string   `help:"Linux distribution name (e.g. ubuntu, debian, centos)" required:""`
	Version string   `help:"Distribution version (e.g. 22.04)" required:""`
	Pkg     []string `help:"Package names with versions (e.g. openssl=3.0.2)" required:""`
}

func (c *LinuxAuditCmd) Run(ctx context.Context, globals *CLI, deps *Deps) error {
	if err := validateNonScanFormat(globals.Output); err != nil {
		return err
	}
	if globals.Offline {
		return fmt.Errorf("linux audit does not support offline mode")
	}
	if deps.Intel == nil {
		return fmt.Errorf("VULNERS_API_KEY is required for audit")
	}

	result, err := deps.Intel.LinuxAudit(ctx, c.Distro, c.Version, c.Pkg)
	if err != nil {
		return fmt.Errorf("linux audit failed: %w", err)
	}

	w, closer, werr := outputWriter(globals)
	if werr != nil {
		return werr
	}
	defer func() { _ = closer() }()

	return writeIntelOutput(w, globals, "audit linux", result, nil)
}
