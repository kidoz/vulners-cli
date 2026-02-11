package cmd

import (
	"fmt"
	"reflect"

	"github.com/invopop/jsonschema"
	vulners "github.com/kidoz/go-vulners"
	"github.com/kidoz/go-vulners/vscanner"
	"github.com/kidoz/vulners-cli/internal/intel"
	"github.com/kidoz/vulners-cli/internal/model"
)

// typedIntelOutput is a generic version of IntelOutput with concrete Data type
// for schema generation purposes.
type typedIntelOutput[T any] struct {
	SchemaVersion string `json:"schemaVersion" jsonschema:"description=Schema version (semver)"`
	Command       string `json:"command" jsonschema:"description=Command that produced this output"`
	Data          T      `json:"data" jsonschema:"description=Command output payload"`
	Meta          any    `json:"meta,omitempty" jsonschema:"description=Optional metadata"`
}

// commandSchemaTypes maps command names to the reflect.Type of their output.
var commandSchemaTypes = map[string]reflect.Type{
	// Scan commands
	"scan": reflect.TypeFor[ScanOutput](),
	"plan": reflect.TypeFor[typedIntelOutput[PlanOutput]](),

	// Intel commands
	"version":      reflect.TypeFor[typedIntelOutput[VersionInfo]](),
	"search":       reflect.TypeFor[typedIntelOutput[intel.SearchResult]](),
	"cve":          reflect.TypeFor[typedIntelOutput[CVEOutput]](),
	"cpe":          reflect.TypeFor[typedIntelOutput[vulners.CPESearchResult]](),
	"doctor":       reflect.TypeFor[typedIntelOutput[DoctorOutput]](),
	"spec":         reflect.TypeFor[typedIntelOutput[SpecOutput]](),
	"stix":         reflect.TypeFor[typedIntelOutput[vulners.StixBundle]](),
	"suggest":      reflect.TypeFor[typedIntelOutput[[]string]](),
	"autocomplete": reflect.TypeFor[typedIntelOutput[[]string]](),

	// Audit commands
	"audit-linux":   reflect.TypeFor[typedIntelOutput[vulners.AuditResult]](),
	"audit-windows": reflect.TypeFor[typedIntelOutput[vulners.AuditResult]](),
	"audit-host":    reflect.TypeFor[typedIntelOutput[vulners.AuditResult]](),
	"audit-win":     reflect.TypeFor[typedIntelOutput[vulners.AuditResult]](),

	// Report commands
	"report-summary": reflect.TypeFor[typedIntelOutput[vulners.VulnsSummary]](),
	"report-vulns":   reflect.TypeFor[typedIntelOutput[[]vulners.VulnItem]](),
	"report-hosts":   reflect.TypeFor[typedIntelOutput[[]vulners.HostVuln]](),
	"report-scans":   reflect.TypeFor[typedIntelOutput[[]vulners.ScanItem]](),
	"report-ips":     reflect.TypeFor[typedIntelOutput[vulners.IPSummary]](),

	// Webhook commands
	"webhook-list": reflect.TypeFor[typedIntelOutput[[]vulners.Webhook]](),
	"webhook-add":  reflect.TypeFor[typedIntelOutput[vulners.Webhook]](),
	"webhook-get":  reflect.TypeFor[typedIntelOutput[vulners.Webhook]](),
	"webhook-read": reflect.TypeFor[typedIntelOutput[vulners.WebhookData]](),

	// Subscription commands
	"subscription-list":   reflect.TypeFor[typedIntelOutput[[]vulners.Subscription]](),
	"subscription-get":    reflect.TypeFor[typedIntelOutput[vulners.Subscription]](),
	"subscription-create": reflect.TypeFor[typedIntelOutput[vulners.Subscription]](),

	// VScanner commands
	"vscan-project-list":   reflect.TypeFor[typedIntelOutput[[]vscanner.Project]](),
	"vscan-project-get":    reflect.TypeFor[typedIntelOutput[vscanner.Project]](),
	"vscan-project-create": reflect.TypeFor[typedIntelOutput[vscanner.Project]](),
	"vscan-task-list":      reflect.TypeFor[typedIntelOutput[[]vscanner.Task]](),
	"vscan-task-get":       reflect.TypeFor[typedIntelOutput[vscanner.Task]](),
	"vscan-task-create":    reflect.TypeFor[typedIntelOutput[vscanner.Task]](),
	"vscan-result-list":    reflect.TypeFor[typedIntelOutput[[]vscanner.Result]](),
	"vscan-result-get":     reflect.TypeFor[typedIntelOutput[vscanner.Result]](),
	"vscan-result-stats":   reflect.TypeFor[typedIntelOutput[vscanner.Statistics]](),
	"vscan-result-hosts":   reflect.TypeFor[typedIntelOutput[[]vscanner.HostSummary]](),
	"vscan-result-host":    reflect.TypeFor[typedIntelOutput[vscanner.HostDetail]](),
	"vscan-result-vulns":   reflect.TypeFor[typedIntelOutput[[]vscanner.VulnSummary]](),
	"vscan-license":        reflect.TypeFor[typedIntelOutput[[]vscanner.License]](),

	// Model types (standalone)
	"component": reflect.TypeFor[model.Component](),
	"finding":   reflect.TypeFor[model.Finding](),
}

// generateSchema generates a JSON Schema for the given command name.
func generateSchema(command string) (*jsonschema.Schema, error) {
	typ, ok := commandSchemaTypes[command]
	if !ok {
		return nil, fmt.Errorf("unknown command %q; use 'vulners spec --schema list' to see available schemas", command)
	}
	r := &jsonschema.Reflector{
		DoNotReference: false,
	}
	return r.ReflectFromType(typ), nil
}

// listSchemaCommands returns a sorted list of available schema command names.
func listSchemaCommands() []string {
	names := make([]string, 0, len(commandSchemaTypes))
	for name := range commandSchemaTypes {
		names = append(names, name)
	}
	// Sort for deterministic output.
	sortStrings(names)
	return names
}

func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j] < s[j-1]; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
}
