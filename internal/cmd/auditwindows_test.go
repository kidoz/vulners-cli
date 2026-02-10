package cmd

import (
	"context"
	"testing"

	vulners "github.com/kidoz/go-vulners"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWindowsAuditCmd_Happy(t *testing.T) {
	client := &mockIntelClient{
		kbAuditFn: func(_ context.Context, osName string, kbList []string) (*vulners.AuditResult, error) {
			assert.Equal(t, "Windows 10", osName)
			assert.Equal(t, []string{"KB5001234"}, kbList)
			return &vulners.AuditResult{}, nil
		},
	}

	cmd := WindowsAuditCmd{OS: "Windows 10", KB: []string{"KB5001234"}}
	captureStdout(t, func() {
		err := cmd.Run(context.Background(), jsonCLI(), testDeps(client))
		require.NoError(t, err)
	})
}

func TestWindowsAuditCmd_NilIntel(t *testing.T) {
	cmd := WindowsAuditCmd{OS: "Windows 10", KB: []string{"KB5001234"}}
	err := cmd.Run(context.Background(), jsonCLI(), nilDeps())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "VULNERS_API_KEY")
}

func TestWindowsAuditCmd_OfflineRejected(t *testing.T) {
	cmd := WindowsAuditCmd{OS: "Windows 10", KB: []string{"KB5001234"}}
	err := cmd.Run(context.Background(), offlineCLI(), testDeps(&mockIntelClient{}))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "does not support offline mode")
}
