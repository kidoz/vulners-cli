package cmd

import (
	"context"
	"testing"

	vulners "github.com/kidoz/go-vulners"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLinuxAuditCmd_Happy(t *testing.T) {
	client := &mockIntelClient{
		linuxAuditFn: func(_ context.Context, osName, osVersion string, packages []string) (*vulners.AuditResult, error) {
			assert.Equal(t, "ubuntu", osName)
			assert.Equal(t, "22.04", osVersion)
			assert.Equal(t, []string{"openssl=3.0.2"}, packages)
			return &vulners.AuditResult{}, nil
		},
	}

	cmd := LinuxAuditCmd{Distro: "ubuntu", Version: "22.04", Pkg: []string{"openssl=3.0.2"}}
	captureStdout(t, func() {
		err := cmd.Run(context.Background(), jsonCLI(), testDeps(client))
		require.NoError(t, err)
	})
}

func TestLinuxAuditCmd_NilIntel(t *testing.T) {
	cmd := LinuxAuditCmd{Distro: "ubuntu", Version: "22.04", Pkg: []string{"pkg=1.0"}}
	err := cmd.Run(context.Background(), jsonCLI(), nilDeps())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "VULNERS_API_KEY")
}

func TestLinuxAuditCmd_OfflineRejected(t *testing.T) {
	cmd := LinuxAuditCmd{Distro: "ubuntu", Version: "22.04", Pkg: []string{"pkg=1.0"}}
	err := cmd.Run(context.Background(), offlineCLI(), testDeps(&mockIntelClient{}))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "does not support offline mode")
}

func TestLinuxAuditCmd_SarifRejected(t *testing.T) {
	cmd := LinuxAuditCmd{Distro: "ubuntu", Version: "22.04", Pkg: []string{"pkg=1.0"}}
	err := cmd.Run(context.Background(), sarifCLI(), testDeps(&mockIntelClient{}))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "only supported for scan commands")
}
