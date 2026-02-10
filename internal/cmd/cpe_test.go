package cmd

import (
	"context"
	"testing"

	vulners "github.com/kidoz/go-vulners"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCPECmd_Happy(t *testing.T) {
	client := &mockIntelClient{
		searchCPEFn: func(_ context.Context, product, vendor string, limit int) (*vulners.CPESearchResult, error) {
			assert.Equal(t, "openssl", product)
			assert.Equal(t, "openssl_project", vendor)
			return &vulners.CPESearchResult{}, nil
		},
	}

	cmd := CPECmd{Product: "openssl", Vendor: "openssl_project", Limit: 10}
	captureStdout(t, func() {
		err := cmd.Run(context.Background(), jsonCLI(), testDeps(client), nopStore())
		require.NoError(t, err)
	})
}

func TestCPECmd_VendorDefault(t *testing.T) {
	var capturedVendor string
	client := &mockIntelClient{
		searchCPEFn: func(_ context.Context, product, vendor string, _ int) (*vulners.CPESearchResult, error) {
			capturedVendor = vendor
			return &vulners.CPESearchResult{}, nil
		},
	}

	cmd := CPECmd{Product: "nginx", Vendor: "", Limit: 10}
	captureStdout(t, func() {
		err := cmd.Run(context.Background(), jsonCLI(), testDeps(client), nopStore())
		require.NoError(t, err)
	})
	assert.Equal(t, "nginx", capturedVendor, "vendor should default to product name")
}

func TestCPECmd_NilIntel(t *testing.T) {
	cmd := CPECmd{Product: "test", Limit: 10}
	err := cmd.Run(context.Background(), jsonCLI(), nilDeps(), nopStore())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "VULNERS_API_KEY")
}

func TestCPECmd_Offline(t *testing.T) {
	store := &mockStore{
		searchBulletinsFn: func(_ context.Context, query string, limit, offset int) ([]vulners.Bulletin, int, error) {
			return []vulners.Bulletin{{ID: "CPE-RESULT"}}, 1, nil
		},
	}

	cmd := CPECmd{Product: "openssl", Limit: 10}
	out := captureStdout(t, func() {
		err := cmd.Run(context.Background(), offlineCLI(), nilDeps(), store)
		require.NoError(t, err)
	})
	assert.Contains(t, string(out), "CPE-RESULT")
}

func TestCPECmd_SarifRejected(t *testing.T) {
	cmd := CPECmd{Product: "test", Limit: 10}
	err := cmd.Run(context.Background(), sarifCLI(), testDeps(&mockIntelClient{}), nopStore())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "only supported for scan commands")
}
