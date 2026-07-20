package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"

	vulners "github.com/kidoz/go-vulners"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSmartAuditCmd_Happy(t *testing.T) {
	client := &mockIntelClient{
		smartAuditFn: func(_ context.Context, software []string, catalog string) (*vulners.SmartAuditResult, error) {
			assert.Equal(t, []string{"Adobe Reader 5.3", "OpenSSL 1.0.1"}, software)
			assert.Equal(t, "official", catalog)
			return &vulners.SmartAuditResult{
				Items: []vulners.SmartAuditItem{
					{
						Input: "OpenSSL 1.0.1",
						CPE:   "cpe:2.3:a:openssl:openssl:1.0.1:*:*:*:*:*:*:*",
						Vulnerabilities: []vulners.SmartAuditVulnerability{
							{ID: "CVE-2014-0160"},
						},
					},
				},
			}, nil
		},
	}

	command := SmartAuditCmd{
		Software: []string{"Adobe Reader 5.3", "OpenSSL 1.0.1"},
		Catalog:  "official",
	}
	out := captureStdout(t, func() {
		err := command.Run(context.Background(), jsonCLI(), testDeps(client))
		require.NoError(t, err)
	})

	var result struct {
		Command string                   `json:"command"`
		Data    vulners.SmartAuditResult `json:"data"`
	}
	require.NoError(t, json.Unmarshal(out, &result))
	assert.Equal(t, "audit smart", result.Command)
	require.Len(t, result.Data.Items, 1)
	assert.Equal(t, "OpenSSL 1.0.1", result.Data.Items[0].Input)
	require.Len(t, result.Data.Items[0].Vulnerabilities, 1)
	assert.Equal(t, "CVE-2014-0160", result.Data.Items[0].Vulnerabilities[0].ID)
}

func TestSmartAuditCmd_Errors(t *testing.T) {
	tests := []struct {
		name    string
		command SmartAuditCmd
		globals *CLI
		deps    *Deps
		wantErr string
	}{
		{
			name:    "missing API key",
			command: SmartAuditCmd{Software: []string{"OpenSSL 1.0.1"}},
			globals: jsonCLI(),
			deps:    nilDeps(),
			wantErr: "VULNERS_API_KEY",
		},
		{
			name:    "offline mode",
			command: SmartAuditCmd{Software: []string{"OpenSSL 1.0.1"}},
			globals: offlineCLI(),
			deps:    testDeps(&mockIntelClient{}),
			wantErr: "offline",
		},
		{
			name:    "missing software",
			command: SmartAuditCmd{},
			globals: jsonCLI(),
			deps:    testDeps(&mockIntelClient{}),
			wantErr: "no software descriptions",
		},
		{
			name:    "API error",
			command: SmartAuditCmd{Software: []string{"OpenSSL 1.0.1"}},
			globals: jsonCLI(),
			deps: testDeps(&mockIntelClient{
				smartAuditFn: func(context.Context, []string, string) (*vulners.SmartAuditResult, error) {
					return nil, fmt.Errorf("boom")
				},
			}),
			wantErr: "smart audit failed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.command.Run(context.Background(), tt.globals, tt.deps)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.wantErr)
		})
	}
}
