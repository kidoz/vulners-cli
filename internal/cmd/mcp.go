package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"

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
				"Use search/cve for threat intel lookups, scan_repo for local Go repository scanning, " +
				"and doctor to check environment health.",
		},
	)

	registerMCPTools(server, deps, store, logger)

	return server.Run(ctx, &mcp.StdioTransport{})
}

func registerMCPTools(server *mcp.Server, deps *Deps, store cache.Store, logger *slog.Logger) {
	registerSearchTool(server, deps)
	registerCVETool(server, deps, store)
	registerScanRepoTool(server, deps, store, logger)
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

// --- doctor tool ---

func registerDoctorTool(server *mcp.Server, deps *Deps, store cache.Store) {
	mcp.AddTool(server, &mcp.Tool{
		Name:        "doctor",
		Description: "Run environment health checks. Verifies API key, offline database, syft, Go version, and network connectivity.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, args struct{}) (*mcp.CallToolResult, any, error) {
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
