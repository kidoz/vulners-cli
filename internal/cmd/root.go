package cmd

import "github.com/kidoz/vulners-cli/internal/model"

// Re-export exit codes for use by main.go.
const (
	ExitOK       = model.ExitOK
	ExitFindings = model.ExitFindings
)

const ExitRuntimeError = model.ExitRuntimeError

// CLI is the root Kong command structure.
type CLI struct {
	// Global flags
	Output      string   `help:"Output format (json, table, sarif, html, cyclonedx)" enum:"json,table,sarif,html,cyclonedx" default:"json"`
	Quiet       bool     `help:"Suppress non-error output" short:"q"`
	Verbose     bool     `help:"Enable verbose/debug output" short:"v"`
	Offline     bool     `help:"Use offline database only"`
	Agent       bool     `help:"Machine-friendly mode: JSON output, quiet, deterministic ordering, no color"`
	NoColor     bool     `help:"Disable colored log output" name:"no-color"`
	OutputFile  string   `help:"Write output to file instead of stdout" name:"output-file" type:"path"`
	MaxFindings int      `help:"Maximum findings to include in output (0 = unlimited)" default:"0" name:"max-findings"`
	SummaryOnly bool     `help:"Output summary and top findings only (omit full lists)" name:"summary-only"`
	FailOn      string   `help:"Fail with exit code 1 if findings at or above severity (low, medium, high, critical)" default:""`
	Ignore      []string `help:"CVE IDs to ignore"`
	VEX         string   `help:"Path to OpenVEX document for suppression"`
	Fields      []string `help:"Select top-level JSON fields to include in output (JSON only)" name:"fields"`
	Plan        bool     `help:"Show what a scan would do without executing it" name:"plan"`

	// Commands
	Version      VersionCmd      `cmd:"" help:"Print version information"`
	Search       SearchCmd       `cmd:"" help:"Search Vulners database"`
	CVE          CVECmd          `cmd:"" name:"cve" help:"Look up a CVE by ID"`
	CPE          CPECmd          `cmd:"" name:"cpe" help:"Search by CPE"`
	Audit        AuditCmd        `cmd:"" help:"Audit OS packages"`
	Scan         ScanCmd         `cmd:"" help:"Scan targets for vulnerabilities"`
	Offline_     OfflineCmd      `cmd:"" name:"offline" help:"Manage offline database"`
	STIX         StixCmd         `cmd:"" name:"stix" help:"Export STIX bundle for a bulletin or CVE"`
	Autocomplete AutocompleteCmd `cmd:"" help:"Autocomplete a Vulners search query"`
	Suggest      SuggestCmd      `cmd:"" help:"Get field value suggestions for search queries"`
	Doctor       DoctorCmd       `cmd:"" help:"Run environment health checks"`
	Spec         SpecCmd         `cmd:"" help:"Output machine-readable command and flag definitions"`
	Report       ReportCmd       `cmd:"" help:"Account-level vulnerability reports"`
}
