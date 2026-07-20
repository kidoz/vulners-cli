package cmd

import (
	"context"
	"encoding/json"
	"io"
	"testing"

	vulners "github.com/kidoz/go-vulners"
	"github.com/kidoz/vulners-cli/internal/intel"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMCP_RegistersTools(t *testing.T) {
	server := mcp.NewServer(
		&mcp.Implementation{Name: "test", Version: "0.0.1"},
		nil,
	)

	deps := &Deps{Intel: &mockIntelClient{}}
	registerMCPTools(server, deps, nopStore(), discardLogger())

	clientTransport, serverTransport := mcp.NewInMemoryTransports()

	session, err := server.Connect(context.Background(), serverTransport, nil)
	require.NoError(t, err)
	defer func() { _ = session.Close() }()

	client := mcp.NewClient(&mcp.Implementation{Name: "test-client", Version: "1.0"}, nil)
	clientSession, err := client.Connect(context.Background(), clientTransport, nil)
	require.NoError(t, err)
	defer func() { _ = clientSession.Close() }()

	result, err := clientSession.ListTools(context.Background(), nil)
	require.NoError(t, err)

	toolNames := make(map[string]bool)
	for _, tool := range result.Tools {
		toolNames[tool.Name] = true
	}

	assert.True(t, toolNames["search"], "should have search tool")
	assert.True(t, toolNames["cve"], "should have cve tool")
	assert.True(t, toolNames["cpe"], "should have cpe tool")
	assert.True(t, toolNames["scan_repo"], "should have scan_repo tool")
	assert.True(t, toolNames["sbom_audit"], "should have sbom_audit tool")
	assert.True(t, toolNames["doctor"], "should have doctor tool")
}

func TestMCP_SearchTool(t *testing.T) {
	client := &mockIntelClient{
		searchFn: func(_ context.Context, query string, limit, offset int) (*intel.SearchResult, error) {
			return &intel.SearchResult{
				Total: 1,
				Bulletins: []vulners.Bulletin{
					{ID: "CVE-2021-44228", Type: "cve"},
				},
			}, nil
		},
	}

	result := callMCPTool(t, client, "search", map[string]any{
		"query": "log4j",
		"limit": 5,
	})

	require.False(t, result.IsError, "search should succeed")
	require.Len(t, result.Content, 1)

	text := extractText(t, result.Content[0])
	var sr intel.SearchResult
	require.NoError(t, json.Unmarshal([]byte(text), &sr))
	assert.Equal(t, 1, sr.Total)
}

func TestMCP_CPETool(t *testing.T) {
	client := &mockIntelClient{
		searchCPEFn: func(_ context.Context, product, vendor string, limit int) (*vulners.CPESearchResult, error) {
			assert.Equal(t, "chrome", product)
			assert.Equal(t, "google", vendor)
			return &vulners.CPESearchResult{BestMatch: "cpe:2.3:a:google:chrome:-", CPEs: []string{"cpe:2.3:a:google:chrome:-"}}, nil
		},
	}

	result := callMCPTool(t, client, "cpe", map[string]any{
		"product": "chrome",
		"vendor":  "google",
		"limit":   5,
	})

	require.False(t, result.IsError, "cpe should succeed")
	require.Len(t, result.Content, 1)

	text := extractText(t, result.Content[0])
	var cpe vulners.CPESearchResult
	require.NoError(t, json.Unmarshal([]byte(text), &cpe))
	assert.Equal(t, "cpe:2.3:a:google:chrome:-", cpe.BestMatch)
	require.Len(t, cpe.CPEs, 1)
}

func TestMCP_SBOMAuditTool(t *testing.T) {
	client := &mockIntelClient{
		sbomAuditFn: func(_ context.Context, sbom io.Reader) (*vulners.SBOMAuditResult, error) {
			data, _ := io.ReadAll(sbom)
			assert.Contains(t, string(data), "cyclonedx")
			return &vulners.SBOMAuditResult{Packages: []vulners.SBOMPackageResult{{Package: "log4j", Version: "2.14.0"}}}, nil
		},
	}

	result := callMCPTool(t, client, "sbom_audit", map[string]any{
		"sbom":   `{"bomFormat":"cyclonedx"}`,
		"format": "cyclonedx",
	})

	require.False(t, result.IsError, "sbom_audit should succeed")
	require.Len(t, result.Content, 1)

	text := extractText(t, result.Content[0])
	var audit vulners.SBOMAuditResult
	require.NoError(t, json.Unmarshal([]byte(text), &audit))
	require.Len(t, audit.Packages, 1)
}

func TestMCP_SBOMAuditTool_EmptySBOM(t *testing.T) {
	result := callMCPTool(t, &mockIntelClient{}, "sbom_audit", map[string]any{
		"sbom": "",
	})

	assert.True(t, result.IsError, "empty sbom should error")
}

func TestMCP_DoctorTool(t *testing.T) {
	result := callMCPTool(t, &mockIntelClient{}, "doctor", map[string]any{})

	require.False(t, result.IsError)
	require.Len(t, result.Content, 1)

	text := extractText(t, result.Content[0])
	var output DoctorOutput
	require.NoError(t, json.Unmarshal([]byte(text), &output))
	assert.True(t, len(output.Checks) > 0)
}

func TestMCP_SearchTool_NoAPIKey(t *testing.T) {
	server := mcp.NewServer(
		&mcp.Implementation{Name: "test", Version: "0.0.1"},
		nil,
	)
	deps := &Deps{Intel: nil}
	registerMCPTools(server, deps, nopStore(), discardLogger())

	clientTransport, serverTransport := mcp.NewInMemoryTransports()

	session, err := server.Connect(context.Background(), serverTransport, nil)
	require.NoError(t, err)
	defer func() { _ = session.Close() }()

	mcpClient := mcp.NewClient(&mcp.Implementation{Name: "test-client", Version: "1.0"}, nil)
	clientSession, err := mcpClient.Connect(context.Background(), clientTransport, nil)
	require.NoError(t, err)
	defer func() { _ = clientSession.Close() }()

	result, err := clientSession.CallTool(context.Background(), &mcp.CallToolParams{
		Name:      "search",
		Arguments: map[string]any{"query": "test"},
	})
	require.NoError(t, err)
	assert.True(t, result.IsError, "should error without API key")
}

// --- helpers ---

func callMCPTool(t *testing.T, client *mockIntelClient, toolName string, args map[string]any) *mcp.CallToolResult {
	t.Helper()

	server := mcp.NewServer(
		&mcp.Implementation{Name: "test", Version: "0.0.1"},
		nil,
	)
	deps := &Deps{Intel: client}
	registerMCPTools(server, deps, nopStore(), discardLogger())

	clientTransport, serverTransport := mcp.NewInMemoryTransports()

	session, err := server.Connect(context.Background(), serverTransport, nil)
	require.NoError(t, err)
	defer func() { _ = session.Close() }()

	mcpClient := mcp.NewClient(&mcp.Implementation{Name: "test-client", Version: "1.0"}, nil)
	clientSession, err := mcpClient.Connect(context.Background(), clientTransport, nil)
	require.NoError(t, err)
	defer func() { _ = clientSession.Close() }()

	result, err := clientSession.CallTool(context.Background(), &mcp.CallToolParams{
		Name:      toolName,
		Arguments: args,
	})
	require.NoError(t, err)
	return result
}

func extractText(t *testing.T, content mcp.Content) string {
	t.Helper()
	b, err := content.MarshalJSON()
	require.NoError(t, err)
	var m map[string]any
	require.NoError(t, json.Unmarshal(b, &m))
	text, ok := m["text"].(string)
	require.True(t, ok, "content should have text field, got: %v", m)
	return text
}
