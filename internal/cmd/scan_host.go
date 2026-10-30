package cmd

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"time"

	vulners "github.com/kidoz/go-vulners"
	"github.com/kidoz/vulners-cli/internal/host"
	"github.com/kidoz/vulners-cli/internal/model"
)

// ScanHostCmd represents the 'scan host' command.
type ScanHostCmd struct {
	Target       string        `arg:"" help:"Target host (e.g. 'local', 'ssh://user@host', 'winrms://user@host')" default:"local"`
	IdentityFile string        `help:"Path to SSH private key file (e.g., ~/.ssh/id_rsa)"`
	PasswordEnv  string        `help:"Environment variable containing the password (for SSH or WinRM)"`
	AskPass      bool          `help:"Interactively prompt for password"`
	Insecure     bool          `help:"Allow insecure connections (e.g., skip SSH host key verification or WinRM HTTPS TLS verification)"`
	Timeout      time.Duration `help:"Connection timeout for remote scanning" default:"10s"`
}

func (c *ScanHostCmd) Run(ctx context.Context, globals *CLI, deps *Deps, logger *slog.Logger) error {
	if globals.Offline {
		return fmt.Errorf("host scanning does not support offline mode")
	}
	if err := host.ValidateTarget(c.Target); err != nil {
		return err
	}
	if globals.Plan {
		return writeScanPlan(globals, PlanOutput{Target: c.Target, Mode: "online", HasAPIKey: deps.Intel != nil, InventoryPending: true, Steps: []string{"connect to target", "detect OS and collect inventory", "audit inventory", "apply policy and report"}})
	}
	if deps.Intel == nil {
		return usageErrorf("VULNERS_API_KEY is required for host scanning")
	}
	if _, err := newPolicy(globals); err != nil {
		return err
	}
	factory := deps.HostExecutorFactory
	if factory == nil {
		factory = host.NewExecutorFromURI
	}
	executor, err := factory(ctx, c.Target, host.ExecutorOptions{IdentityFile: c.IdentityFile, PasswordEnv: c.PasswordEnv, AskPass: c.AskPass, Insecure: c.Insecure, Timeout: c.Timeout})
	if err != nil {
		return fmt.Errorf("failed to initialize executor: %w", err)
	}
	defer func() { _ = executor.Close() }()
	scanner := host.NewScanner(executor, logger)
	info, err := scanner.DetectOS(ctx)
	if err != nil {
		return fmt.Errorf("OS detection failed: %w", err)
	}
	components, result, err := auditHostInventory(ctx, deps, scanner, info)
	if err != nil {
		return err
	}
	if result == nil {
		return fmt.Errorf("host audit returned no result")
	}
	findings := convertAuditFindings(result)
	for i := range findings {
		if findings[i].ComponentRef == "" {
			findings[i].ComponentRef = c.Target
		}
	}
	return finalizeScan(globals, c.Target, components, findings)
}

func auditHostInventory(ctx context.Context, deps *Deps, scanner *host.Scanner, info *host.OSInfo) ([]model.Component, *vulners.AuditResult, error) {
	if info.Family == host.FamilyWindows {
		return auditWindowsInventory(ctx, deps, scanner, info)
	}
	packages, err := scanner.GatherPackages(ctx, info)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to gather packages: %w", err)
	}
	if len(packages) == 0 {
		return nil, nil, fmt.Errorf("no packages found on the target host")
	}
	components := make([]model.Component, 0, len(packages))
	for _, pkg := range packages {
		fields := strings.Fields(pkg)
		component := model.Component{Type: string(info.Family), Name: fields[0]}
		if len(fields) > 1 {
			component.Version = fields[1]
		}
		components = append(components, component)
	}
	result, err := deps.Intel.LinuxAudit(ctx, info.Distro, info.Version, packages)
	if err != nil {
		return nil, nil, fmt.Errorf("linux audit failed: %w", err)
	}
	return components, result, nil
}

func auditWindowsInventory(ctx context.Context, deps *Deps, scanner *host.Scanner, info *host.OSInfo) ([]model.Component, *vulners.AuditResult, error) {
	kbs, software, err := scanner.GatherWindows(ctx, info)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to gather Windows inventory: %w", err)
	}
	if len(kbs) == 0 && len(software) == 0 {
		return nil, nil, fmt.Errorf("no KBs or installed software found on the target host")
	}
	var components []model.Component
	for _, kb := range kbs {
		components = append(components, model.Component{Type: "windows-kb", Name: kb})
	}
	for _, item := range software {
		components = append(components, model.Component{Type: "windows-software", Name: item.Software, Version: item.Version})
	}
	result, err := deps.Intel.WinAudit(ctx, host.NormalizeWindowsOS(info.OSName, info.BuildNumber), info.Version, kbs, software)
	if err != nil {
		return nil, nil, fmt.Errorf("windows audit failed: %w", err)
	}
	return components, result, nil
}
