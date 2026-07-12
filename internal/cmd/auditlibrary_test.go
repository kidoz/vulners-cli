package cmd

import (
	"context"
	"fmt"
	"testing"

	vulners "github.com/kidoz/go-vulners"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLibraryAuditCmd_Happy(t *testing.T) {
	client := &mockIntelClient{
		libraryAuditFn: func(_ context.Context, packages []string) (*vulners.PackageAuditResult, error) {
			assert.Equal(t, []string{"pkg:npm/lodash@4.17.20"}, packages)
			return &vulners.PackageAuditResult{
				TotalPackages: 1,
				Issues: []vulners.PackageAuditIssue{
					{Package: "pkg:npm/lodash@4.17.20"},
				},
			}, nil
		},
	}

	cmd := LibraryAuditCmd{Purl: []string{"pkg:npm/lodash@4.17.20"}}
	out := captureStdout(t, func() {
		err := cmd.Run(context.Background(), jsonCLI(), testDeps(client))
		require.NoError(t, err)
	})
	assert.Contains(t, string(out), "audit library")
	assert.Contains(t, string(out), "lodash")
}

func TestLibraryAuditCmd_NilIntel(t *testing.T) {
	cmd := LibraryAuditCmd{Purl: []string{"pkg:npm/lodash@4.17.20"}}
	err := cmd.Run(context.Background(), jsonCLI(), nilDeps())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "VULNERS_API_KEY")
}

func TestLibraryAuditCmd_Offline(t *testing.T) {
	cmd := LibraryAuditCmd{Purl: []string{"pkg:npm/lodash@4.17.20"}}
	err := cmd.Run(context.Background(), offlineCLI(), testDeps(&mockIntelClient{}))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "offline")
}

func TestLibraryAuditCmd_APIError(t *testing.T) {
	client := &mockIntelClient{
		libraryAuditFn: func(context.Context, []string) (*vulners.PackageAuditResult, error) {
			return nil, fmt.Errorf("boom")
		},
	}

	cmd := LibraryAuditCmd{Purl: []string{"pkg:npm/lodash@4.17.20"}}
	err := cmd.Run(context.Background(), jsonCLI(), testDeps(client))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "library audit failed")
}
