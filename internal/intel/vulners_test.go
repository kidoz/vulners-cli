package intel

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	vulners "github.com/kidoz/go-vulners"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestVulnersClient_SmartAudit(t *testing.T) {
	type smartAuditRequest struct {
		Software []string `json:"software"`
		Catalog  string   `json:"catalog"`
	}

	requests := make(chan smartAuditRequest, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/api/v4/audit/smart" {
			http.Error(w, "unexpected request", http.StatusBadRequest)
			return
		}

		var request smartAuditRequest
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		requests <- request

		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"result":[{"input":"OpenSSL 1.0.1","confidence":0.91,"vulnerabilities":[]}]}`))
	}))
	defer server.Close()

	client, err := vulners.NewClient("test-key", vulners.WithBaseURL(server.URL))
	require.NoError(t, err)
	wrapper := &VulnersClient{
		client: client,
		logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}

	result, err := wrapper.SmartAudit(context.Background(), []string{"OpenSSL 1.0.1"}, "extended")
	require.NoError(t, err)
	require.Len(t, result.Items, 1)
	assert.Equal(t, "OpenSSL 1.0.1", result.Items[0].Input)
	assert.Equal(t, 0.91, result.Items[0].Confidence)

	request := <-requests
	assert.Equal(t, []string{"OpenSSL 1.0.1"}, request.Software)
	assert.Equal(t, "extended", request.Catalog)
}

func TestVulnersClient_SBOMAuditPayloads(t *testing.T) {
	fixture, err := os.ReadFile("../../testdata/api/sbom_audit.json")
	require.NoError(t, err)
	for _, format := range []string{"cyclonedx", "spdx"} {
		input, err := os.ReadFile("../../testdata/" + format + ".json")
		require.NoError(t, err)
		for _, legacy := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/legacy=%v", format, legacy), func(t *testing.T) {
				response := string(fixture)
				if legacy {
					response = strings.ReplaceAll(response, `{"cve": "CVE-TEST", "epss": 0.42, "percentile": 0.95}`, `"CVE-TEST"`)
				}
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					assert.Equal(t, "/api/v4/audit/sbom", r.URL.Path)
					assert.Equal(t, http.MethodPost, r.Method)
					part, _, readErr := r.FormFile("file")
					if readErr != nil {
						t.Error(readErr)
						http.Error(w, "missing SBOM", http.StatusBadRequest)
						return
					}
					defer func() { _ = part.Close() }()
					uploaded, readErr := io.ReadAll(part)
					assert.NoError(t, readErr)
					assert.JSONEq(t, string(input), string(uploaded))
					w.Header().Set("Content-Type", "application/json")
					_, _ = io.WriteString(w, response)
				}))
				defer server.Close()
				client, err := vulners.NewClient("test-key", vulners.WithBaseURL(server.URL))
				require.NoError(t, err)
				wrapper := &VulnersClient{client: client, logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
				result, err := wrapper.SBOMAudit(context.Background(), bytes.NewReader(input))
				require.NoError(t, err)
				require.Len(t, result.Packages, 1)
				require.Len(t, result.Packages[0].ApplicableAdvisories, 1)
				metrics := result.Packages[0].ApplicableAdvisories[0].Metrics
				require.NotNil(t, metrics)
				require.Len(t, metrics.EPSS, 1)
				assert.Equal(t, "CVE-TEST", metrics.EPSS[0].Cve)
				if !legacy {
					assert.Equal(t, 0.42, metrics.EPSS[0].Epss)
				}
			})
		}
	}
}
