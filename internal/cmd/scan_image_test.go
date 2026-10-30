package cmd

import (
	"context"
	"io"
	"testing"

	vulners "github.com/kidoz/go-vulners"
	"github.com/kidoz/vulners-cli/internal/inventory"
	"github.com/kidoz/vulners-cli/internal/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseDistroFlag(t *testing.T) {
	tests := []struct {
		input   string
		name    string
		version string
		wantErr bool
	}{
		{"alpine/3.18", "alpine", "3.18", false},
		{"Ubuntu/22.04", "ubuntu", "22.04", false},
		{"debian/12", "debian", "12", false},
		{"", "", "", true},
		{"alpine", "", "", true},
		{"/3.18", "", "", true},
		{"alpine/", "", "", true},
	}

	for _, tt := range tests {
		di, err := parseDistroFlag(tt.input)
		if tt.wantErr {
			assert.Error(t, err, "input: %q", tt.input)
			continue
		}
		require.NoError(t, err, "input: %q", tt.input)
		assert.Equal(t, tt.name, di.Name)
		assert.Equal(t, tt.version, di.Version)
	}
}

func TestSplitByEcosystem(t *testing.T) {
	components := []model.Component{
		{Name: "musl", Ecosystem: "apk"},
		{Name: "libssl", Ecosystem: "deb"},
		{Name: "zlib", Ecosystem: "rpm"},
		{Name: "express", Ecosystem: "npm"},
		{Name: "cobra", Ecosystem: "golang"},
		{Name: "unknown", Ecosystem: ""},
	}

	os, app := splitByEcosystem(components)
	assert.Len(t, os, 3, "expected 3 OS packages")
	assert.Len(t, app, 3, "expected 3 app packages")

	for _, c := range os {
		assert.True(t, inventory.IsOSEcosystem(c.Ecosystem), "expected OS ecosystem for %s", c.Name)
	}
}

func TestFormatOSPackages(t *testing.T) {
	comps := []model.Component{
		{Name: "musl", Version: "1.2.4-r2"},
		{Name: "openssl", Version: "3.0.12-r0"},
		{Name: "rpm-pkg", Version: "1.2-3", Ecosystem: "rpm", PURL: "pkg:rpm/rpm-pkg@1.2-3?arch=aarch64"},
	}

	pkgs := formatOSPackages(comps)
	assert.Equal(t, []string{"musl 1.2.4-r2", "openssl 3.0.12-r0", "rpm-pkg 1.2-3 aarch64"}, pkgs)
}

func TestConvertAuditFindings(t *testing.T) {
	result := &vulners.AuditResult{
		Vulnerabilities: []vulners.Vulnerability{
			{
				Package:    "openssl",
				Version:    "3.0.2",
				BulletinID: "USN-5710-1",
				CVEList:    []string{"CVE-2022-3602", "CVE-2022-3786"},
				CVSS:       &vulners.CVSS{Score: 7.5},
				Fix:        "3.0.7",
			},
			{
				Package:    "zlib",
				Version:    "1.2.11",
				BulletinID: "DSA-5218-1",
				CVSS:       nil,
				Fix:        "1.2.12",
			},
		},
	}

	findings := convertAuditFindings(result)
	require.Len(t, findings, 2)

	assert.Equal(t, "USN-5710-1", findings[0].VulnID)
	assert.Equal(t, 7.5, findings[0].CVSS)
	assert.Equal(t, "high", findings[0].Severity)
	assert.Equal(t, "openssl@3.0.2", findings[0].ComponentRef)
	assert.Equal(t, "3.0.7", findings[0].Fix)
	assert.Equal(t, []string{"CVE-2022-3602", "CVE-2022-3786"}, findings[0].Aliases)

	assert.Equal(t, "DSA-5218-1", findings[1].VulnID)
	assert.Equal(t, 0.0, findings[1].CVSS)
	assert.Equal(t, "none", findings[1].Severity)
	assert.Equal(t, "zlib@1.2.11", findings[1].ComponentRef)
}

func TestScanImageOnline_PreservesSBOMOSFindings(t *testing.T) {
	for _, withApp := range []bool{false, true} {
		comps := []model.Component{{Name: "libc6", Version: "2.36", Ecosystem: "deb", PURL: "pkg:deb/debian/libc6@2.36?arch=arm64"}}
		if withApp {
			comps = append(comps, model.Component{Name: "app", Version: "1"})
		}
		client := &mockIntelClient{
			linuxAuditFn: func(_ context.Context, _, _ string, pkgs []string) (*vulners.AuditResult, error) {
				assert.Equal(t, []string{"libc6 2.36 arm64"}, pkgs)
				return &vulners.AuditResult{Vulnerabilities: []vulners.Vulnerability{{Package: "libc6", Version: "2.36", BulletinID: "CVE-SHARED"}}}, nil
			},
			sbomAuditFn: func(context.Context, io.Reader) (*vulners.SBOMAuditResult, error) {
				return &vulners.SBOMAuditResult{Packages: []vulners.SBOMPackageResult{{Package: "libc6", Version: "2.36", ApplicableAdvisories: []vulners.SBOMAdvisory{{ID: "CVE-SHARED"}, {ID: "CVE-SBOM-ONLY"}}}}}, nil
			},
		}
		findings, mode, err := (&ScanImageCmd{}).scanImageOnline(context.Background(), testDeps(client), discardLogger(), &inventory.SBOMResult{Components: comps, Distro: &inventory.DistroInfo{Name: "debian", Version: "12"}})
		require.NoError(t, err)
		assert.Equal(t, "hybrid", mode)
		require.Len(t, findings, 2)
		assert.Equal(t, "CVE-SBOM-ONLY", findings[1].VulnID)
	}
}

func TestFormatOSPackages_MissingImageArch(t *testing.T) {
	assert.Empty(t, formatOSPackages([]model.Component{{Name: "libc6", Version: "2.36", Ecosystem: "deb"}}))
}

func TestScanImageOnline_UnknownArchUsesSBOM(t *testing.T) {
	client := &mockIntelClient{
		linuxAuditFn: func(context.Context, string, string, []string) (*vulners.AuditResult, error) {
			t.Fatal("missing architecture must use SBOM")
			return nil, nil
		},
		sbomAuditFn: func(context.Context, io.Reader) (*vulners.SBOMAuditResult, error) {
			return &vulners.SBOMAuditResult{Packages: []vulners.SBOMPackageResult{{Package: "libc6", Version: "2.36", ApplicableAdvisories: []vulners.SBOMAdvisory{{ID: "CVE-SBOM"}}}}}, nil
		},
	}
	findings, mode, err := (&ScanImageCmd{}).scanImageOnline(context.Background(), testDeps(client), discardLogger(), &inventory.SBOMResult{Components: []model.Component{{Name: "libc6", Version: "2.36", Ecosystem: "deb"}}, Distro: &inventory.DistroInfo{Name: "debian", Version: "12"}})
	require.NoError(t, err)
	assert.Equal(t, "sbom", mode)
	require.Len(t, findings, 1)
}
