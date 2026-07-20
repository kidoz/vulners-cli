package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"

	"github.com/kidoz/vulners-cli/internal/cache"
	"github.com/kidoz/vulners-cli/internal/inventory"
	"github.com/kidoz/vulners-cli/internal/matcher"
	"github.com/kidoz/vulners-cli/internal/model"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// MCPCmd runs vulners-cli as an MCP (Model Context Protocol) server.
type MCPCmd struct{}

func (c *MCPCmd) Run(ctx context.Context, deps *Deps, store cache.Store, logger *slog.Logger) error {
	server := mcp.NewServer(
		&mcp.Implementation{
			Name:    "vulners-cli",
			Version: Version,
		},
		&mcp.ServerOptions{
			Instructions: "Vulners vulnerability intelligence and scanning tools. " +
				"Use search/cve for threat intel lookups, cpe for product/vendor search, " +
				"scan_repo for local Go repository scanning, sbom_audit for CycloneDX/SPDX SBOM audit, " +
				"audit_smart to resolve free-form software descriptions and audit them, " +
				"and doctor to check environment health.",
		},
	)

	registerMCPTools(server, deps, store, logger)

	return server.Run(ctx, &mcp.StdioTransport{})
}

func registerMCPTools(server *mcp.Server, deps *Deps, store cache.Store, logger *slog.Logger) {
	registerSearchTool(server, deps)
	registerCVETool(server, deps, store)
	registerCPETool(server, deps)
	registerScanRepoTool(server, deps, store, logger)
	registerSBOMAuditTool(server, deps)
	registerSmartAuditTool(server, deps)
	registerDoctorTool(server, deps, store)
}

// --- search tool ---

type searchArgs struct {
	Query  string `json:"query" jsonschema:"Vulners search query"`
	Limit  int    `json:"limit,omitempty" jsonschema:"Maximum results to return (default 10)"`
	Offset int    `json:"offset,omitempty" jsonschema:"Pagination offset (default 0)"`
}

func registerSearchTool(server *mcp.Server, deps *Deps) {
	mcp.AddTool(server, &mcp.Tool{
		Name:        "search",
		Description: "Search the Vulners vulnerability database. Returns bulletins matching the query.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, args searchArgs) (*mcp.CallToolResult, any, error) {
		if deps.Intel == nil {
			return mcpError("VULNERS_API_KEY is required for search"), nil, nil
		}
		limit := args.Limit
		if limit <= 0 {
			limit = 10
		}
		result, err := deps.Intel.Search(ctx, args.Query, limit, args.Offset)
		if err != nil {
			return mcpError(fmt.Sprintf("search failed: %v", err)), nil, nil
		}
		return mcpJSON(result)
	})
}

// --- cve tool ---

type cveArgs struct {
	ID string `json:"id" jsonschema:"CVE identifier (e.g. CVE-2021-44228)"`
}

func registerCVETool(server *mcp.Server, deps *Deps, store cache.Store) {
	mcp.AddTool(server, &mcp.Tool{
		Name:        "cve",
		Description: "Look up a CVE by ID. Returns detailed bulletin information including CVSS scores and affected software.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, args cveArgs) (*mcp.CallToolResult, any, error) {
		// Try offline first if no API key.
		if deps.Intel == nil {
			bulletin, err := store.GetBulletin(ctx, args.ID)
			if err != nil {
				return mcpError(fmt.Sprintf("CVE lookup failed (offline): %v", err)), nil, nil
			}
			return mcpJSON(bulletin)
		}
		bulletin, err := deps.Intel.GetBulletin(ctx, args.ID)
		if err != nil {
			return mcpError(fmt.Sprintf("CVE lookup failed: %v", err)), nil, nil
		}
		return mcpJSON(bulletin)
	})
}

// --- cpe tool ---

type cpeArgs struct {
	Product string `json:"product" jsonschema:"Product name to search"`
	Vendor  string `json:"vendor,omitempty" jsonschema:"Vendor name (defaults to product)"`
	Limit   int    `json:"limit,omitempty" jsonschema:"Maximum results to return (default 10)"`
}

func registerCPETool(server *mcp.Server, deps *Deps) {
	mcp.AddTool(server, &mcp.Tool{
		Name:        "cpe",
		Description: "Search by Common Platform Enumeration (CPE). Returns bulletins matching a product (and optional vendor).",
	}, func(ctx context.Context, req *mcp.CallToolRequest, args cpeArgs) (*mcp.CallToolResult, any, error) {
		if deps.Intel == nil {
			return mcpError("VULNERS_API_KEY is required for CPE search"), nil, nil
		}
		limit := args.Limit
		if limit <= 0 {
			limit = 10
		}
		vendor := args.Vendor
		if vendor == "" {
			vendor = args.Product
		}
		result, err := deps.Intel.SearchCPE(ctx, args.Product, vendor, limit)
		if err != nil {
			return mcpError(fmt.Sprintf("CPE search failed: %v", err)), nil, nil
		}
		return mcpJSON(result)
	})
}

// --- scan_repo tool ---

type scanRepoArgs struct {
	Path string `json:"path" jsonschema:"Path to Go repository to scan (default .)"`
}

func registerScanRepoTool(server *mcp.Server, deps *Deps, store cache.Store, logger *slog.Logger) {
	mcp.AddTool(server, &mcp.Tool{
		Name:        "scan_repo",
		Description: "Scan a Go repository for vulnerable dependencies. Analyzes go.mod and returns findings with severity and CVSS scores.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, args scanRepoArgs) (*mcp.CallToolResult, any, error) {
		path := args.Path
		if path == "" {
			path = "."
		}

		collector := &inventory.GoModCollector{}
		components, err := collector.Collect(ctx, path)
		if err != nil {
			return mcpError(fmt.Sprintf("inventory collection failed: %v", err)), nil, nil
		}

		var findings []model.Finding
		if deps.Intel != nil {
			m := matcher.NewMatcher(deps.Intel, logger)
			findings, err = m.Match(ctx, components)
			if err != nil {
				return mcpError(fmt.Sprintf("matching failed: %v", err)), nil, nil
			}
		} else {
			findings, err = scanOfflineComponents(ctx, store, components, logger)
			if err != nil {
				return mcpError(fmt.Sprintf("offline scan failed: %v", err)), nil, nil
			}
		}

		output := ScanOutput{
			SchemaVersion: "1.0.0",
			Target:        path,
			Components:    components,
			Findings:      findings,
			Summary:       summarize(components, findings),
		}
		return mcpJSON(output)
	})
}

// --- sbom_audit tool ---

type sbomAuditArgs struct {
	SBOM   string `json:"sbom" jsonschema:"SBOM document content (CycloneDX or SPDX JSON)"`
	Format string `json:"format,omitempty" jsonschema:"SBOM format: cyclonedx or spdx (default cyclonedx)"`
}

func registerSBOMAuditTool(server *mcp.Server, deps *Deps) {
	mcp.AddTool(server, &mcp.Tool{
		Name:        "sbom_audit",
		Description: "Audit a CycloneDX or SPDX SBOM document for vulnerable packages. Pass the SBOM document content as a string.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, args sbomAuditArgs) (*mcp.CallToolResult, any, error) {
		if deps.Intel == nil {
			return mcpError("VULNERS_API_KEY is required for SBOM audit"), nil, nil
		}
		if strings.TrimSpace(args.SBOM) == "" {
			return mcpError("sbom argument is required"), nil, nil
		}
		result, err := deps.Intel.SBOMAudit(ctx, strings.NewReader(args.SBOM))
		if err != nil {
			return mcpError(fmt.Sprintf("SBOM audit failed: %v", err)), nil, nil
		}
		return mcpJSON(result)
	})
}

// --- audit_smart tool ---

type auditSmartArgs struct {
	Software []string `json:"software" jsonschema:"Free-form software descriptions to resolve and audit (e.g. \"Apache 2.4.49\")"`
	Catalog  string   `json:"catalog,omitempty" jsonschema:"Vulnerability catalog: official or extended (default official)"`
}

func registerSmartAuditTool(server *mcp.Server, deps *Deps) {
	mcp.AddTool(server, &mcp.Tool{
		Name:        "audit_smart",
		Description: "Resolve free-form software descriptions (e.g. \"Apache 2.4.49\") to CPE/PURL and audit them for vulnerabilities. Best for triaging assets described in plain language.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, args auditSmartArgs) (*mcp.CallToolResult, any, error) {
		if deps.Intel == nil {
			return mcpError("VULNERS_API_KEY is required for smart audit"), nil, nil
		}
		if len(args.Software) == 0 {
			return mcpError("software argument is required"), nil, nil
		}
		catalog := args.Catalog
		if catalog == "" {
			catalog = "official"
		}
		result, err := deps.Intel.SmartAudit(ctx, args.Software, catalog)
		if err != nil {
			return mcpError(fmt.Sprintf("smart audit failed: %v", err)), nil, nil
		}
		return mcpJSON(result)
	})
}

// --- doctor tool ---

func registerDoctorTool(server *mcp.Server, deps *Deps, store cache.Store) {
	mcp.AddTool(server, &mcp.Tool{
		Name:        "doctor",
		Description: "Run environment health checks. Verifies API key, offline database, Go version, and network connectivity.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, args struct{}) (*mcp.CallToolResult, any, error) {
		var checks []CheckResult
		checks = append(checks, checkAPIKey(deps))
		checks = append(checks, checkOfflineDB(ctx, store))
		checks = append(checks, checkGo())
		checks = append(checks, checkNetwork(ctx, deps))

		allPass := true
		for _, ch := range checks {
			if ch.Status == "fail" {
				allPass = false
				break
			}
		}

		output := DoctorOutput{Checks: checks, AllPass: allPass}
		return mcpJSON(output)
	})
}

// --- helpers ---

func mcpJSON(data any) (*mcp.CallToolResult, any, error) {
	b, err := json.Marshal(data)
	if err != nil {
		return mcpError(fmt.Sprintf("JSON marshal error: %v", err)), nil, nil
	}
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: string(b)}},
	}, nil, nil
}

func mcpError(msg string) *mcp.CallToolResult {
	r := &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: msg}},
	}
	r.SetError(fmt.Errorf("%s", msg))
	return r
}
