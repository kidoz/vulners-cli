package cmd

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/alecthomas/kong"
	"github.com/kidoz/vulners-cli/internal/intel"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	vulners "github.com/kidoz/go-vulners"
)

// TestStdoutIsValidJSON verifies that every command that supports JSON output
// writes exactly one valid JSON object to stdout and nothing else.
// This is the core agent contract: stdout = one JSON object when --output json.
func TestStdoutIsValidJSON(t *testing.T) {
	client := &mockIntelClient{
		searchFn: func(_ context.Context, _ string, _, _ int) (*intel.SearchResult, error) {
			return &intel.SearchResult{Total: 1, Bulletins: []vulners.Bulletin{{ID: "CVE-2021-44228"}}}, nil
		},
		getBulletinFn: func(_ context.Context, id string) (*vulners.Bulletin, error) {
			return &vulners.Bulletin{ID: id}, nil
		},
		searchCPEFn: func(_ context.Context, _, _ string, _ int) (*vulners.CPESearchResult, error) {
			return &vulners.CPESearchResult{}, nil
		},
		makeSTIXBundleByIDFn: func(_ context.Context, _ string) (*vulners.StixBundle, error) {
			return &vulners.StixBundle{}, nil
		},
		queryAutocompleteFn: func(_ context.Context, _ string) ([]string, error) {
			return []string{"suggestion"}, nil
		},
		getSuggestionFn: func(_ context.Context, _ string) ([]string, error) {
			return []string{"cve"}, nil
		},
	}

	deps := testDeps(client)
	cli := jsonCLI()

	tests := []struct {
		name string
		run  func() error
	}{
		{"version", func() error {
			return (&VersionCmd{}).Run(cli)
		}},
		{"search", func() error {
			return (&SearchCmd{Query: "test", Limit: 10}).Run(context.Background(), cli, deps, nopStore())
		}},
		{"cve", func() error {
			return (&CVECmd{ID: "CVE-2021-44228"}).Run(context.Background(), cli, deps, nopStore())
		}},
		{"cpe", func() error {
			return (&CPECmd{Product: "openssl", Limit: 10}).Run(context.Background(), cli, deps, nopStore())
		}},
		{"stix", func() error {
			return (&StixCmd{ID: "TEST-123"}).Run(context.Background(), cli, deps)
		}},
		{"autocomplete", func() error {
			return (&AutocompleteCmd{Query: "test"}).Run(context.Background(), cli, deps)
		}},
		{"suggest", func() error {
			return (&SuggestCmd{Field: "type"}).Run(context.Background(), cli, deps)
		}},
		{"doctor", func() error {
			// Doctor with API key + working network returns allPass=true, exit 0.
			return (&DoctorCmd{}).Run(context.Background(), cli, deps, nopStore())
		}},
		{"spec", func() error {
			var c CLI
			k, err := kong.New(&c, kong.Exit(func(_ int) {}))
			if err != nil {
				return err
			}
			return (&SpecCmd{}).Run(cli, k)
		}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			out := captureStdout(t, func() {
				err := tt.run()
				require.NoError(t, err)
			})

			assert.NotEmpty(t, out, "stdout should not be empty")

			var parsed json.RawMessage
			err := json.Unmarshal(out, &parsed)
			assert.NoError(t, err, "stdout must be valid JSON, got: %s", string(out))
		})
	}
}
