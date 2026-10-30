package cmd

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	vulners "github.com/kidoz/go-vulners"
	"github.com/kidoz/vulners-cli/internal/host"
	"github.com/kidoz/vulners-cli/internal/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type hostPolicyExecutor struct{ windows bool }

func (e *hostPolicyExecutor) Execute(_ context.Context, command string) (string, error) {
	if e.windows {
		switch command {
		case "uname -s":
			return "", nil
		case "Get-CimInstance Win32_OperatingSystem | Select-Object Caption,Version,BuildNumber | ConvertTo-Csv -NoTypeInformation":
			return "\"Caption\",\"Version\",\"BuildNumber\"\n\"Microsoft Windows 11\",\"10.0\",\"22631\"", nil
		default:
			return "KB123456", nil
		}
	}
	switch command {
	case "uname -s":
		return "Linux", nil
	case "cat /etc/os-release":
		return "ID=debian\nVERSION_ID=12", nil
	default:
		return "pkg 1.0 amd64", nil
	}
}
func (*hostPolicyExecutor) Close() error { return nil }

func TestHostAndWebScanPolicy(t *testing.T) {
	for _, kind := range []string{"linux", "windows", "windows-aggregate", "web"} {
		for _, suppression := range []string{"none", "ignore", "vex", "unrelated-vex"} {
			t.Run(kind+"/"+suppression, func(t *testing.T) { checkHostOrWebPolicy(t, kind, suppression) })
		}
	}
}

func checkHostOrWebPolicy(t *testing.T, kind, suppression string) {
	t.Helper()
	audit := func(context.Context, string, string, []string) (*vulners.AuditResult, error) {
		result := &vulners.AuditResult{Vulnerabilities: []vulners.Vulnerability{{Package: "pkg", Version: "1.0", BulletinID: "CVE-TEST", CVSS: &vulners.CVSS{Score: 9.8}}}}
		if kind == "windows-aggregate" {
			result.Vulnerabilities[0].CVSS = nil
			result.CVSSScore = 9.8
		}
		return result, nil
	}
	client := &mockIntelClient{
		linuxAuditFn: audit,
		winAuditFn: func(ctx context.Context, osName, version string, kbs []string, _ []vulners.WinAuditItem) (*vulners.AuditResult, error) {
			return audit(ctx, osName, version, kbs)
		},
		getWebVulnsFn: func(context.Context, []string, any) (map[string][]vulners.WebVulnerability, error) {
			return map[string][]vulners.WebVulnerability{"/path": {{ID: "CVE-TEST", Metrics: map[string]any{"cvss": 9.8}}}}, nil
		},
	}
	deps := testDeps(client)
	deps.HostExecutorFactory = func(context.Context, string, host.ExecutorOptions) (host.Executor, error) {
		return &hostPolicyExecutor{windows: strings.HasPrefix(kind, "windows")}, nil
	}
	cli := jsonCLI()
	cli.FailOn = "low"
	if suppression == "ignore" {
		cli.Ignore = []string{"cve-test"}
	}
	if suppression == "vex" || suppression == "unrelated-vex" {
		cli.VEX = filepath.Join(t.TempDir(), "vex.json")
		require.NoError(t, os.WriteFile(cli.VEX, []byte(`{"statements":[{"vulnerability":{"name":"CVE-TEST"},"products":["pkg@1.0"],"status":"not_affected"}]}`), 0o600))
	}
	if suppression == "unrelated-vex" {
		require.NoError(t, os.WriteFile(cli.VEX, []byte(`{"statements":[{"vulnerability":{"name":"CVE-TEST"},"products":["other@1.0"],"status":"not_affected"}]}`), 0o600))
	}
	var runErr error
	out := captureStdout(t, func() {
		if kind == "web" {
			runErr = (&ScanWebCmd{Path: []string{"/path"}, Software: "pkg", SoftwareVersion: "1.0"}).Run(context.Background(), cli, deps)
		} else {
			runErr = (&ScanHostCmd{Target: "local"}).Run(context.Background(), cli, deps, discardLogger())
		}
	})
	if suppression == "none" || suppression == "unrelated-vex" {
		var exitErr *model.ExitError
		require.ErrorAs(t, runErr, &exitErr)
		assert.Equal(t, model.ExitFindings, exitErr.Code)
	} else {
		require.NoError(t, runErr)
	}
	var result ScanOutput
	require.NoError(t, json.Unmarshal(out, &result))
	if suppression == "none" || suppression == "unrelated-vex" {
		require.Len(t, result.Findings, 1)
		assert.Equal(t, "critical", result.Findings[0].Severity)
	} else {
		assert.Empty(t, result.Findings)
		assert.NotContains(t, string(out), "CVE-TEST")
	}
}

func TestHostAndWebPlanAvoidsExecution(t *testing.T) {
	deps := testDeps(&mockIntelClient{getWebVulnsFn: func(context.Context, []string, any) (map[string][]vulners.WebVulnerability, error) {
		t.Fatal("web API called by plan")
		return nil, nil
	}})
	deps.HostExecutorFactory = func(context.Context, string, host.ExecutorOptions) (host.Executor, error) {
		t.Fatal("executor created by plan")
		return nil, nil
	}
	for _, hasKey := range []bool{true, false} {
		plannedDeps := *deps
		if !hasKey {
			plannedDeps.Intel = nil
		}
		for _, kind := range []string{"host", "web"} {
			cli := jsonCLI()
			cli.Plan = true
			out := captureStdout(t, func() {
				if kind == "host" {
					require.NoError(t, (&ScanHostCmd{Target: "ssh://user@example.com", AskPass: true}).Run(context.Background(), cli, &plannedDeps, discardLogger()))
				} else {
					require.NoError(t, (&ScanWebCmd{Path: []string{"/path"}}).Run(context.Background(), cli, &plannedDeps))
				}
			})
			var result struct {
				Command string     `json:"command"`
				Data    PlanOutput `json:"data"`
			}
			require.NoError(t, json.Unmarshal(out, &result))
			assert.Equal(t, "plan", result.Command)
			assert.Equal(t, hasKey, result.Data.HasAPIKey)
			assert.NotEmpty(t, result.Data.Steps)
			assert.Equal(t, kind == "host", result.Data.InventoryPending)
		}
	}
}

func TestHostPlanRejectsEmbeddedPassword(t *testing.T) {
	cli := jsonCLI()
	cli.Plan = true
	out := captureStdout(t, func() {
		err := (&ScanHostCmd{Target: "ssh://user:fake-secret@example.com"}).Run(context.Background(), cli, nilDeps(), discardLogger()) //nolint:gosec // Deliberately invalid URI with a fake credential to test rejection.
		require.Error(t, err)
		assert.NotContains(t, err.Error(), "fake-secret")
	})
	assert.Empty(t, out)
}
