package cmd

import (
	"context"
	"runtime"
	"testing"

	vulners "github.com/kidoz/go-vulners"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func expectedArch() string {
	if runtime.GOOS != "linux" {
		return "amd64"
	}
	switch runtime.GOARCH {
	case "amd64":
		return "amd64"
	case "arm64":
		return "arm64"
	case "386":
		return "i386"
	case "arm":
		return "armhf"
	default:
		return "amd64"
	}
}

func TestLinuxAuditCmd_Happy(t *testing.T) {
	arch := expectedArch()
	client := &mockIntelClient{
		linuxAuditFn: func(_ context.Context, osName, osVersion string, packages []string) (*vulners.AuditResult, error) {
			assert.Equal(t, "ubuntu", osName)
			assert.Equal(t, "22.04", osVersion)
			assert.Equal(t, []string{"openssl 3.0.2 " + arch}, packages)
			return &vulners.AuditResult{}, nil
		},
	}

	cmd := LinuxAuditCmd{Distro: "ubuntu", Version: "22.04", Pkg: []string{"openssl=3.0.2"}}
	captureStdout(t, func() {
		err := cmd.Run(context.Background(), jsonCLI(), testDeps(client))
		require.NoError(t, err)
	})
}

func TestLinuxAuditCmd_MultiplePackages(t *testing.T) {
	arch := expectedArch()
	client := &mockIntelClient{
		linuxAuditFn: func(_ context.Context, osName, osVersion string, packages []string) (*vulners.AuditResult, error) {
			assert.Equal(t, []string{"openssl 3.0.2 " + arch, "curl 7.81.0 " + arch}, packages)
			return &vulners.AuditResult{}, nil
		},
	}

	cmd := LinuxAuditCmd{
		Distro:  "ubuntu",
		Version: "22.04",
		Pkg:     []string{"openssl=3.0.2", "curl=7.81.0"},
	}
	captureStdout(t, func() {
		err := cmd.Run(context.Background(), jsonCLI(), testDeps(client))
		require.NoError(t, err)
	})
}

func TestLinuxAuditCmd_ExplicitArch(t *testing.T) {
	client := &mockIntelClient{
		linuxAuditFn: func(_ context.Context, osName, osVersion string, packages []string) (*vulners.AuditResult, error) {
			assert.Equal(t, []string{"openssl 3.0.2 i386"}, packages)
			return &vulners.AuditResult{}, nil
		},
	}

	cmd := LinuxAuditCmd{Distro: "ubuntu", Version: "22.04", Pkg: []string{"openssl=3.0.2"}, Arch: "i386"}
	captureStdout(t, func() {
		err := cmd.Run(context.Background(), jsonCLI(), testDeps(client))
		require.NoError(t, err)
	})
}

func TestLinuxAuditCmd_ThreeFieldsPassThrough(t *testing.T) {
	client := &mockIntelClient{
		linuxAuditFn: func(_ context.Context, _, _ string, packages []string) (*vulners.AuditResult, error) {
			assert.Equal(t, []string{"openssl 3.0.2-0ubuntu1 amd64"}, packages)
			return &vulners.AuditResult{}, nil
		},
	}

	cmd := LinuxAuditCmd{Distro: "ubuntu", Version: "22.04", Pkg: []string{"openssl 3.0.2-0ubuntu1 amd64"}}
	captureStdout(t, func() {
		err := cmd.Run(context.Background(), jsonCLI(), testDeps(client))
		require.NoError(t, err)
	})
}

func TestLinuxAuditCmd_RPMNoArch(t *testing.T) {
	client := &mockIntelClient{
		linuxAuditFn: func(_ context.Context, _, _ string, packages []string) (*vulners.AuditResult, error) {
			// RPM-based distros should NOT get arch appended
			assert.Equal(t, []string{"openssl 1.0.2k"}, packages)
			return &vulners.AuditResult{}, nil
		},
	}

	cmd := LinuxAuditCmd{Distro: "centos", Version: "7", Pkg: []string{"openssl=1.0.2k"}}
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
