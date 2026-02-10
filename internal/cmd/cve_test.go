package cmd

import (
	"context"
	"fmt"
	"testing"

	vulners "github.com/kidoz/go-vulners"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCVECmd_Happy(t *testing.T) {
	client := &mockIntelClient{
		getBulletinFn: func(_ context.Context, id string) (*vulners.Bulletin, error) {
			assert.Equal(t, "CVE-2021-44228", id)
			return &vulners.Bulletin{ID: "CVE-2021-44228"}, nil
		},
	}

	cmd := CVECmd{ID: "CVE-2021-44228"}
	out := captureStdout(t, func() {
		err := cmd.Run(context.Background(), jsonCLI(), testDeps(client), nopStore())
		require.NoError(t, err)
	})
	assert.Contains(t, string(out), "CVE-2021-44228")
}

func TestCVECmd_References(t *testing.T) {
	client := &mockIntelClient{
		getBulletinFn: func(context.Context, string) (*vulners.Bulletin, error) {
			return &vulners.Bulletin{ID: "CVE-2021-44228"}, nil
		},
		getBulletinRefsFn: func(_ context.Context, id string) ([]string, error) {
			return []string{"https://example.com/ref1"}, nil
		},
	}

	cmd := CVECmd{ID: "CVE-2021-44228", References: true}
	out := captureStdout(t, func() {
		err := cmd.Run(context.Background(), jsonCLI(), testDeps(client), nopStore())
		require.NoError(t, err)
	})
	assert.Contains(t, string(out), "ref1")
}

func TestCVECmd_History(t *testing.T) {
	client := &mockIntelClient{
		getBulletinFn: func(context.Context, string) (*vulners.Bulletin, error) {
			return &vulners.Bulletin{ID: "CVE-2021-44228"}, nil
		},
		getBulletinHistoryFn: func(_ context.Context, id string) ([]vulners.HistoryEntry, error) {
			return []vulners.HistoryEntry{{Description: "initial publish"}}, nil
		},
	}

	cmd := CVECmd{ID: "CVE-2021-44228", History: true}
	out := captureStdout(t, func() {
		err := cmd.Run(context.Background(), jsonCLI(), testDeps(client), nopStore())
		require.NoError(t, err)
	})
	assert.Contains(t, string(out), "initial publish")
}

func TestCVECmd_BothFlags(t *testing.T) {
	client := &mockIntelClient{
		getBulletinFn: func(context.Context, string) (*vulners.Bulletin, error) {
			return &vulners.Bulletin{ID: "CVE-2021-44228"}, nil
		},
		getBulletinRefsFn: func(context.Context, string) ([]string, error) {
			return []string{"ref"}, nil
		},
		getBulletinHistoryFn: func(context.Context, string) ([]vulners.HistoryEntry, error) {
			return []vulners.HistoryEntry{{Description: "update"}}, nil
		},
	}

	cmd := CVECmd{ID: "CVE-2021-44228", References: true, History: true}
	out := captureStdout(t, func() {
		err := cmd.Run(context.Background(), jsonCLI(), testDeps(client), nopStore())
		require.NoError(t, err)
	})
	output := string(out)
	assert.Contains(t, output, "ref")
	assert.Contains(t, output, "update")
}

func TestCVECmd_NilIntel(t *testing.T) {
	cmd := CVECmd{ID: "CVE-2021-44228"}
	err := cmd.Run(context.Background(), jsonCLI(), nilDeps(), nopStore())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "VULNERS_API_KEY")
}

func TestCVECmd_Offline(t *testing.T) {
	store := &mockStore{
		getBulletinFn: func(_ context.Context, id string) (*vulners.Bulletin, error) {
			return &vulners.Bulletin{ID: id}, nil
		},
	}

	cmd := CVECmd{ID: "CVE-2021-44228"}
	out := captureStdout(t, func() {
		err := cmd.Run(context.Background(), offlineCLI(), nilDeps(), store)
		require.NoError(t, err)
	})
	assert.Contains(t, string(out), "CVE-2021-44228")
}

func TestCVECmd_SarifRejected(t *testing.T) {
	cmd := CVECmd{ID: "CVE-2021-44228"}
	err := cmd.Run(context.Background(), sarifCLI(), testDeps(&mockIntelClient{}), nopStore())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "only supported for scan commands")
}

func TestCVECmd_APIError(t *testing.T) {
	client := &mockIntelClient{
		getBulletinFn: func(context.Context, string) (*vulners.Bulletin, error) {
			return nil, fmt.Errorf("not found")
		},
	}

	cmd := CVECmd{ID: "CVE-0000-0000"}
	err := cmd.Run(context.Background(), jsonCLI(), testDeps(client), nopStore())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "CVE lookup failed")
}
