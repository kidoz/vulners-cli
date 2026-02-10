package cmd

import (
	"context"
	"testing"

	vulners "github.com/kidoz/go-vulners"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestStixCmd_ByID(t *testing.T) {
	called := false
	client := &mockIntelClient{
		makeSTIXBundleByIDFn: func(_ context.Context, id string) (*vulners.StixBundle, error) {
			called = true
			assert.Equal(t, "RHSA-2021:5137", id)
			return &vulners.StixBundle{}, nil
		},
	}

	cmd := StixCmd{ID: "RHSA-2021:5137"}
	captureStdout(t, func() {
		err := cmd.Run(context.Background(), jsonCLI(), testDeps(client))
		require.NoError(t, err)
	})
	assert.True(t, called)
}

func TestStixCmd_ByCVE(t *testing.T) {
	called := false
	client := &mockIntelClient{
		makeSTIXBundleByCVEFn: func(_ context.Context, id string) (*vulners.StixBundle, error) {
			called = true
			assert.Equal(t, "CVE-2021-44228", id)
			return &vulners.StixBundle{}, nil
		},
	}

	cmd := StixCmd{ID: "CVE-2021-44228", ByCVE: true}
	captureStdout(t, func() {
		err := cmd.Run(context.Background(), jsonCLI(), testDeps(client))
		require.NoError(t, err)
	})
	assert.True(t, called)
}

func TestStixCmd_CVEAutoDetect(t *testing.T) {
	called := false
	client := &mockIntelClient{
		makeSTIXBundleByCVEFn: func(_ context.Context, id string) (*vulners.StixBundle, error) {
			called = true
			return &vulners.StixBundle{}, nil
		},
	}

	// CVE- prefix should auto-detect even without ByCVE flag
	cmd := StixCmd{ID: "CVE-2021-44228"}
	captureStdout(t, func() {
		err := cmd.Run(context.Background(), jsonCLI(), testDeps(client))
		require.NoError(t, err)
	})
	assert.True(t, called, "should auto-detect CVE prefix and use ByCVE path")
}

func TestStixCmd_OfflineRejected(t *testing.T) {
	cmd := StixCmd{ID: "CVE-2021-44228"}
	err := cmd.Run(context.Background(), offlineCLI(), testDeps(&mockIntelClient{}))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "does not support offline mode")
}

func TestStixCmd_NilIntel(t *testing.T) {
	cmd := StixCmd{ID: "CVE-2021-44228"}
	err := cmd.Run(context.Background(), jsonCLI(), nilDeps())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "VULNERS_API_KEY")
}
