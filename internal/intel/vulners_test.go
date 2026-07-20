package intel

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
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
