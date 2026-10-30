package cmd

import (
	"context"
	"errors"
	"testing"

	vulners "github.com/kidoz/go-vulners"
	"github.com/kidoz/vulners-cli/internal/cache"
	"github.com/kidoz/vulners-cli/internal/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewPolicyRejectsInvalidFailOn(t *testing.T) {
	cli := jsonCLI()
	cli.FailOn = "garbage"
	_, err := newPolicy(cli)
	var usageErr *model.UsageError
	require.True(t, errors.As(err, &usageErr), "error should be a usage error: %v", err)
}

func TestScanOfflineComponentsUsesStructuredLookup(t *testing.T) {
	store := &mockStore{
		getCollectionMetaFn: func(context.Context) ([]cache.CollectionMeta, error) {
			return []cache.CollectionMeta{{Collection: "cve", Count: 1}}, nil
		},
		matchBulletinsFn: func(_ context.Context, name, version, cpe string) ([]vulners.Bulletin, error) {
			assert.Equal(t, "openssl", name)
			assert.Equal(t, "1.0", version)
			assert.Empty(t, cpe)
			return []vulners.Bulletin{{ID: "CVE-TEST", CVSS3: &vulners.CVSS3{CVSS: vulners.CVSS{Score: 9.8}}}}, nil
		},
	}
	findings, err := scanOfflineComponents(context.Background(), store, []model.Component{{Name: "OpenSSL", Version: "1.0"}}, discardLogger())
	require.NoError(t, err)
	require.Len(t, findings, 1)
	assert.Equal(t, "CVE-TEST", findings[0].VulnID)
	assert.Equal(t, "critical", findings[0].Severity)
}

func TestScanOfflineComponentsFailsOnLookupError(t *testing.T) {
	store := &mockStore{
		getCollectionMetaFn: func(context.Context) ([]cache.CollectionMeta, error) {
			return []cache.CollectionMeta{{Collection: "cve", Count: 1}}, nil
		},
	}
	_, err := scanOfflineComponents(context.Background(), store, []model.Component{{Name: "openssl", Version: "1.0"}}, discardLogger())
	require.Error(t, err)
}
