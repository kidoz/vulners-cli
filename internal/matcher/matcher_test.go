package matcher

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	vulners "github.com/kidoz/go-vulners"
	"github.com/kidoz/vulners-cli/internal/intel"
	"github.com/kidoz/vulners-cli/internal/model"
)

// mockClient implements intel.Client for testing.
type mockClient struct {
	searchFn             func(ctx context.Context, query string, limit, offset int) (*intel.SearchResult, error)
	getBulletinFn        func(ctx context.Context, id string) (*vulners.Bulletin, error)
	getMultipleFn        func(ctx context.Context, ids []string) (map[string]vulners.Bulletin, error)
	getAIScoreFn         func(ctx context.Context, text string) (*vulners.AIScore, error)
	searchExploitsFn     func(ctx context.Context, query string, limit, offset int) (*intel.SearchResult, error)
	getBulletinRefsFn    func(ctx context.Context, id string) ([]string, error)
	getBulletinHistoryFn func(ctx context.Context, id string) ([]vulners.HistoryEntry, error)
}

func (m *mockClient) Search(ctx context.Context, query string, limit, offset int) (*intel.SearchResult, error) {
	if m.searchFn != nil {
		return m.searchFn(ctx, query, limit, offset)
	}
	return &intel.SearchResult{}, nil
}

func (m *mockClient) SearchExploits(ctx context.Context, query string, limit, offset int) (*intel.SearchResult, error) {
	if m.searchExploitsFn != nil {
		return m.searchExploitsFn(ctx, query, limit, offset)
	}
	return &intel.SearchResult{}, nil
}

func (m *mockClient) GetBulletin(ctx context.Context, id string) (*vulners.Bulletin, error) {
	if m.getBulletinFn != nil {
		return m.getBulletinFn(ctx, id)
	}
	return nil, fmt.Errorf("not found")
}

func (m *mockClient) GetMultipleBulletins(ctx context.Context, ids []string) (map[string]vulners.Bulletin, error) {
	if m.getMultipleFn != nil {
		return m.getMultipleFn(ctx, ids)
	}
	return nil, fmt.Errorf("not implemented")
}

func (m *mockClient) GetBulletinReferences(ctx context.Context, id string) ([]string, error) {
	if m.getBulletinRefsFn != nil {
		return m.getBulletinRefsFn(ctx, id)
	}
	return nil, nil
}

func (m *mockClient) GetBulletinHistory(ctx context.Context, id string) ([]vulners.HistoryEntry, error) {
	if m.getBulletinHistoryFn != nil {
		return m.getBulletinHistoryFn(ctx, id)
	}
	return nil, nil
}

func (m *mockClient) GetAIScore(ctx context.Context, text string) (*vulners.AIScore, error) {
	if m.getAIScoreFn != nil {
		return m.getAIScoreFn(ctx, text)
	}
	return nil, fmt.Errorf("not implemented")
}

// Stub implementations for remaining interface methods.
func (m *mockClient) SearchCPE(context.Context, string, string, int) (*vulners.CPESearchResult, error) {
	return nil, nil
}

func (m *mockClient) LinuxAudit(context.Context, string, string, []string) (*vulners.AuditResult, error) {
	return nil, nil
}

func (m *mockClient) KBAudit(context.Context, string, []string) (*vulners.AuditResult, error) {
	return nil, nil
}

func (m *mockClient) HostAudit(context.Context, string, string, []vulners.AuditItem) (*vulners.AuditResult, error) {
	return nil, nil
}

func (m *mockClient) WinAudit(context.Context, string, string, []string, []vulners.WinAuditItem) (*vulners.AuditResult, error) {
	return nil, nil
}

func (m *mockClient) SBOMAudit(_ context.Context, _ io.Reader) (*vulners.SBOMAuditResult, error) {
	return nil, nil
}

func (m *mockClient) FetchCollection(_ context.Context, _ vulners.CollectionType) ([]vulners.Bulletin, error) {
	return nil, nil
}

func (m *mockClient) FetchCollectionUpdate(_ context.Context, _ vulners.CollectionType, _ time.Time) ([]vulners.Bulletin, error) {
	return nil, nil
}

func (m *mockClient) MakeSTIXBundleByID(context.Context, string) (*vulners.StixBundle, error) {
	return nil, nil
}

func (m *mockClient) MakeSTIXBundleByCVE(context.Context, string) (*vulners.StixBundle, error) {
	return nil, nil
}

func (m *mockClient) QueryAutocomplete(context.Context, string) ([]string, error) {
	return nil, nil
}

func (m *mockClient) GetSuggestion(context.Context, string) ([]string, error) {
	return nil, nil
}

func (m *mockClient) VulnsSummaryReport(context.Context, int, int) (*vulners.VulnsSummary, error) {
	return nil, nil
}

func (m *mockClient) VulnsList(context.Context, int, int) ([]vulners.VulnItem, error) {
	return nil, nil
}

func (m *mockClient) HostVulns(context.Context, int, int) ([]vulners.HostVuln, error) {
	return nil, nil
}

func (m *mockClient) ScanList(context.Context, int, int) ([]vulners.ScanItem, error) {
	return nil, nil
}

func (m *mockClient) IPSummaryReport(context.Context) (*vulners.IPSummary, error) {
	return nil, nil
}

func (m *mockClient) ListWebhooks(context.Context) ([]vulners.Webhook, error) { return nil, nil }
func (m *mockClient) AddWebhook(context.Context, string) (*vulners.Webhook, error) {
	return nil, nil
}

func (m *mockClient) GetWebhook(context.Context, string) (*vulners.Webhook, error) {
	return nil, nil
}

func (m *mockClient) ReadWebhook(context.Context, string, bool) (*vulners.WebhookData, error) {
	return nil, nil
}
func (m *mockClient) EnableWebhook(context.Context, string, bool) error { return nil }
func (m *mockClient) DeleteWebhook(context.Context, string) error       { return nil }

func (m *mockClient) ListSubscriptions(context.Context) ([]vulners.Subscription, error) {
	return nil, nil
}

func (m *mockClient) GetSubscription(context.Context, string) (*vulners.Subscription, error) {
	return nil, nil
}

func (m *mockClient) CreateSubscription(context.Context, *vulners.SubscriptionRequest) (*vulners.Subscription, error) {
	return nil, nil
}

func (m *mockClient) UpdateSubscription(context.Context, string, *vulners.SubscriptionRequest) (*vulners.Subscription, error) {
	return nil, nil
}
func (m *mockClient) DeleteSubscription(context.Context, string) error       { return nil }
func (m *mockClient) EnableSubscription(context.Context, string, bool) error { return nil }

func TestMatcher_Match_WithResults(t *testing.T) {
	client := &mockClient{
		searchFn: func(_ context.Context, query string, _, _ int) (*intel.SearchResult, error) {
			return &intel.SearchResult{
				Total: 1,
				Bulletins: []vulners.Bulletin{
					{
						ID:      "CVE-2021-44228",
						CVEList: []string{"CVE-2021-44228"},
						CVSS:    &vulners.CVSS{Score: 10.0},
						Type:    "cve",
						Href:    "https://vulners.com/cve/CVE-2021-44228",
					},
				},
			}, nil
		},
	}

	logger := slog.Default()
	m := NewMatcher(client, logger)

	components := []model.Component{
		{Name: "log4j", Version: "2.14.0", Type: "maven"},
	}

	findings, err := m.Match(context.Background(), components)
	if err != nil {
		t.Fatalf("Match() error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].VulnID != "CVE-2021-44228" {
		t.Errorf("vulnID = %q, want CVE-2021-44228", findings[0].VulnID)
	}
	if findings[0].Severity != "critical" {
		t.Errorf("severity = %q, want critical", findings[0].Severity)
	}
	if findings[0].CVSS != 10.0 {
		t.Errorf("cvss = %f, want 10.0", findings[0].CVSS)
	}
}

func TestMatcher_Match_SearchError(t *testing.T) {
	client := &mockClient{
		searchFn: func(context.Context, string, int, int) (*intel.SearchResult, error) {
			return nil, fmt.Errorf("api error")
		},
	}

	m := NewMatcher(client, slog.Default())
	findings, err := m.Match(context.Background(), []model.Component{
		{Name: "pkg", Version: "1.0"},
	})
	if err != nil {
		t.Fatalf("Match() should not return error for individual failures: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings on error, got %d", len(findings))
	}
}

func TestMatcher_Match_EmptyComponent(t *testing.T) {
	client := &mockClient{}
	m := NewMatcher(client, slog.Default())

	findings, err := m.Match(context.Background(), []model.Component{
		{Name: "", Version: ""},
	})
	if err != nil {
		t.Fatalf("Match() error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for empty component, got %d", len(findings))
	}
}

func TestMatcher_Match_SkipCount(t *testing.T) {
	callCount := 0
	client := &mockClient{
		searchFn: func(context.Context, string, int, int) (*intel.SearchResult, error) {
			callCount++
			return nil, fmt.Errorf("api error %d", callCount)
		},
	}

	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn}))
	m := NewMatcher(client, logger)

	components := []model.Component{
		{Name: "pkg1", Version: "1.0"},
		{Name: "pkg2", Version: "2.0"},
		{Name: "pkg3", Version: "3.0"},
	}

	findings, err := m.Match(context.Background(), components)
	if err != nil {
		t.Fatalf("Match() error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings, got %d", len(findings))
	}

	logOutput := buf.String()
	if !strings.Contains(logOutput, "skipped") {
		t.Errorf("expected skip count warning in logs, got: %s", logOutput)
	}
	if !strings.Contains(logOutput, "3") {
		t.Errorf("expected skip count of 3 in logs, got: %s", logOutput)
	}
}

func TestBuildQuery(t *testing.T) {
	tests := []struct {
		name string
		comp model.Component
		want string
	}{
		{
			name: "with CPE",
			comp: model.Component{CPE: "cpe:/a:vendor:product:1.0"},
			want: "affectedSoftware.cpe:cpe:/a:vendor:product:1.0",
		},
		{
			name: "with name and version",
			comp: model.Component{Name: "log4j", Version: "2.14.0"},
			want: "log4j 2.14.0",
		},
		{
			name: "empty",
			comp: model.Component{},
			want: "",
		},
		{
			name: "name only",
			comp: model.Component{Name: "log4j"},
			want: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := buildQuery(tt.comp)
			if got != tt.want {
				t.Errorf("buildQuery() = %q, want %q", got, tt.want)
			}
		})
	}
}
