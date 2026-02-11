package cmd

import (
	"context"
	"fmt"
	"os/exec"
	"runtime"

	"github.com/kidoz/vulners-cli/internal/cache"
	"github.com/kidoz/vulners-cli/internal/model"
)

// DoctorCmd runs environment health checks.
type DoctorCmd struct{}

// CheckResult is the result of a single health check.
type CheckResult struct {
	Name        string `json:"name"`
	Status      string `json:"status"` // "pass", "fail", "warn"
	Message     string `json:"message,omitempty"`
	Remediation string `json:"remediation,omitempty"`
}

// DoctorOutput is the output of the doctor command.
type DoctorOutput struct {
	Checks  []CheckResult `json:"checks"`
	AllPass bool          `json:"allPass"`
}

func (c *DoctorCmd) Run(ctx context.Context, globals *CLI, deps *Deps, store cache.Store) error {
	if err := validateNonScanFormat(globals.Output); err != nil {
		return err
	}

	var checks []CheckResult

	checks = append(checks, checkAPIKey(deps))
	checks = append(checks, checkOfflineDB(ctx, store))
	checks = append(checks, checkSyft())
	checks = append(checks, checkGo())
	checks = append(checks, checkNetwork(ctx, deps))

	allPass := true
	for _, ch := range checks {
		if ch.Status == "fail" {
			allPass = false
			break
		}
	}

	output := DoctorOutput{
		Checks:  checks,
		AllPass: allPass,
	}

	w, closer, werr := outputWriter(globals)
	if werr != nil {
		return werr
	}
	defer func() { _ = closer() }()

	if err := writeIntelOutput(w, globals, "doctor", output, nil); err != nil {
		return err
	}

	if !allPass {
		return &model.ExitError{Code: model.ExitUsageError}
	}
	return nil
}

func checkAPIKey(deps *Deps) CheckResult {
	if deps.Intel != nil {
		return CheckResult{
			Name:    "api_key",
			Status:  "pass",
			Message: "VULNERS_API_KEY is configured",
		}
	}
	return CheckResult{
		Name:        "api_key",
		Status:      "fail",
		Message:     "VULNERS_API_KEY is not set",
		Remediation: "Set VULNERS_API_KEY environment variable or add api_key to ~/.vulners/config.yaml",
	}
}

func checkOfflineDB(ctx context.Context, store cache.Store) CheckResult {
	metas, err := store.GetCollectionMeta(ctx)
	if err != nil {
		return CheckResult{
			Name:        "offline_db",
			Status:      "warn",
			Message:     fmt.Sprintf("Cannot read offline database: %v", err),
			Remediation: "Run 'vulners offline sync' to initialize the offline database",
		}
	}
	if len(metas) == 0 {
		return CheckResult{
			Name:        "offline_db",
			Status:      "warn",
			Message:     "No offline data synced",
			Remediation: "Run 'vulners offline sync' to populate offline data",
		}
	}
	totalCount := 0
	for _, m := range metas {
		totalCount += m.Count
	}
	return CheckResult{
		Name:    "offline_db",
		Status:  "pass",
		Message: fmt.Sprintf("%d collections synced (%d bulletins)", len(metas), totalCount),
	}
}

func checkSyft() CheckResult {
	path, err := exec.LookPath("syft")
	if err != nil {
		return CheckResult{
			Name:        "syft",
			Status:      "warn",
			Message:     "syft not found in PATH",
			Remediation: "Install syft from https://github.com/anchore/syft (required for image scanning)",
		}
	}
	return CheckResult{
		Name:    "syft",
		Status:  "pass",
		Message: fmt.Sprintf("syft found at %s", path),
	}
}

func checkGo() CheckResult {
	return CheckResult{
		Name:    "go_version",
		Status:  "pass",
		Message: runtime.Version(),
	}
}

func checkNetwork(ctx context.Context, deps *Deps) CheckResult {
	if deps.Intel == nil {
		return CheckResult{
			Name:    "network",
			Status:  "warn",
			Message: "Skipped (no API key configured)",
		}
	}

	// Use a lightweight API call to verify connectivity.
	_, err := deps.Intel.QueryAutocomplete(ctx, "test")
	if err != nil {
		return CheckResult{
			Name:        "network",
			Status:      "fail",
			Message:     fmt.Sprintf("API call failed: %v", err),
			Remediation: "Check network connectivity and API key validity",
		}
	}
	return CheckResult{
		Name:    "network",
		Status:  "pass",
		Message: "Vulners API is reachable",
	}
}
