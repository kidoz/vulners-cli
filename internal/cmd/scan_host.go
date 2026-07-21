package cmd

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/kidoz/vulners-cli/internal/host"
)

// ScanHostCmd represents the 'scan host' command.
type ScanHostCmd struct {
	Target       string        `arg:"" help:"Target host (e.g. 'local', 'ssh://user@host', 'winrm://...')" default:"local"`
	IdentityFile string        `help:"Path to SSH private key file (e.g., ~/.ssh/id_rsa)"`
	PasswordEnv  string        `help:"Environment variable containing the password (for SSH or WinRM)"`
	AskPass      bool          `help:"Interactively prompt for password"`
	Insecure     bool          `help:"Allow insecure connections (e.g., skip SSH host key verification or WinRM HTTPS TLS verification)"`
	Timeout      time.Duration `help:"Connection timeout for remote scanning" default:"10s"`
}

// Run executes the 'scan host' command.
//
//nolint:gocyclo,funlen // Command setup logic naturally requires branching.
func (c *ScanHostCmd) Run(ctx context.Context, globals *CLI, deps *Deps, logger *slog.Logger) error {
	if err := validateNonScanFormat(globals.Output); err != nil {
		return err
	}
	if globals.Offline {
		return fmt.Errorf("host scanning does not support offline mode")
	}
	if deps.Intel == nil {
		return fmt.Errorf("VULNERS_API_KEY is required for host scanning")
	}

	opts := host.ExecutorOptions{
		IdentityFile: c.IdentityFile,
		PasswordEnv:  c.PasswordEnv,
		AskPass:      c.AskPass,
		Insecure:     c.Insecure,
		Timeout:      c.Timeout,
	}

	executor, err := host.NewExecutorFromURI(ctx, c.Target, opts)
	if err != nil {
		return fmt.Errorf("failed to initialize executor: %w", err)
	}
	defer func() { _ = executor.Close() }()

	scanner := host.NewScanner(executor, logger)
	info, err := scanner.DetectOS(ctx)
	if err != nil {
		return fmt.Errorf("OS detection failed: %w", err)
	}

	var result interface{}
	var scanName string

	if info.Family == host.FamilyWindows {
		scanName = "scan host (windows)"
		kbs, software, gErr := scanner.GatherWindows(ctx, info)
		if gErr != nil {
			return fmt.Errorf("failed to gather Windows inventory: %w", gErr)
		}
		if len(kbs) == 0 && len(software) == 0 {
			return fmt.Errorf("no KBs or installed software found on the target host")
		}
		osName := host.NormalizeWindowsOS(info.OSName, info.BuildNumber)
		result, err = deps.Intel.WinAudit(ctx, osName, info.Version, kbs, software)
		if err != nil {
			return fmt.Errorf("windows audit failed: %w", err)
		}
	} else {
		scanName = "scan host (linux)"
		packages, gErr := scanner.GatherPackages(ctx, info)
		if gErr != nil {
			return fmt.Errorf("failed to gather packages: %w", gErr)
		}
		if len(packages) == 0 {
			return fmt.Errorf("no packages found on the target host")
		}
		result, err = deps.Intel.LinuxAudit(ctx, info.Distro, info.Version, packages)
		if err != nil {
			return fmt.Errorf("linux audit failed: %w", err)
		}
	}

	w, closer, werr := outputWriter(globals)
	if werr != nil {
		return werr
	}
	defer func() { _ = closer() }()

	return writeIntelOutput(w, globals, scanName, result, nil)
}
