package matcher

import (
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
func (m *mockClient) CVEAudit(context.Context, string) (*vulners.CVEAuditIssue, error) {
	return nil, nil
}

func (m *mockClient) LinuxAuditV4(context.Context, string, string, []string) (*vulners.PackageAuditResult, error) {
	return nil, nil
}

func (m *mockClient) LibraryAudit(context.Context, []string) (*vulners.PackageAuditResult, error) {
	return nil, nil
}

func (m *mockClient) SmartAudit(context.Context, []string, string) (*vulners.SmartAuditResult, error) {
	return nil, nil
}

func (m *mockClient) GetBulletinWithReferences(context.Context, string) (*vulners.BulletinsWithReferences, error) {
	return nil, nil
}

func (m *mockClient) GetWebVulnerabilities(context.Context, []string, any) (map[string][]vulners.WebVulnerability, error) {
	return nil, nil
}

func (m *mockClient) SearchCPE(context.Context, string, string, int) (*vulners.CPESearchResult, error) {
	return nil, nil
}

func (m *mockClient) LinuxAudit(context.Context, string, string, []string) (*vulners.AuditResult, error) {
	return nil, nil
}

func (m *mockClient) KBAudit(context.Context, string, []string) (*vulners.AuditResult, error) {
	return nil, nil
}

func (m *mockClient) HostAudit(context.Context, string, string, []vulners.AuditItem) (*vulners.SoftwareAuditResult, error) {
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
						ID:               "CVE-2021-44228",
						AffectedSoftware: []vulners.AffectedSoftware{{Name: "log4j", Version: "2.14.0"}},
						CVEList:          []string{"CVE-2021-44228"},
						CVSS:             &vulners.CVSS{Score: 10.0},
						Type:             "cve",
						Href:             "https://vulners.com/cve/CVE-2021-44228",
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
	findings, err := m.Match(context.Background(), []model.Component{{Name: "pkg", Version: "1.0"}})
	if err == nil {
		t.Fatal("Match() should return an error when a lookup fails")
	}
	if len(findings) != 0 {
		t.Fatalf("Match() returned partial findings: %d", len(findings))
	}
	if !strings.Contains(err.Error(), "searching pkg@1.0: api error") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestMatcher_Match_SearchErrorStopsImmediately(t *testing.T) {
	callCount := 0
	client := &mockClient{
		searchFn: func(_ context.Context, _ string, _, _ int) (*intel.SearchResult, error) {
			callCount++
			return nil, fmt.Errorf("api error")
		},
	}

	m := NewMatcher(client, slog.Default())
	_, err := m.Match(context.Background(), []model.Component{
		{Name: "pkg1", Version: "1.0"},
		{Name: "pkg2", Version: "2.0"},
	})
	if err == nil {
		t.Fatal("Match() should fail instead of returning partial results")
	}
	if callCount != 1 {
		t.Fatalf("Search() called %d times, want 1", callCount)
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

func TestBuildQuery(t *testing.T) {
	tests := []struct {
		name string
		comp model.Component
		want string
	}{
		{
			name: "with CPE",
			comp: model.Component{CPE: "cpe:/a:vendor:product:1.0"},
			want: `affectedSoftware.cpe:"cpe:/a:vendor:product:1.0"`,
		},
		{
			name: "with name and version",
			comp: model.Component{Name: "log4j", Version: "2.14.0"},
			want: `affectedSoftware.name:"log4j"`,
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
		{
			name: "special chars in name",
			comp: model.Component{Name: "foo:bar(baz)", Version: "1.0"},
			want: `affectedSoftware.name:"foo:bar(baz)"`,
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

func TestMatcher_RejectsUnrelatedSearchHits(t *testing.T) {
	client := &mockClient{searchFn: func(context.Context, string, int, int) (*intel.SearchResult, error) {
		return &intel.SearchResult{Bulletins: []vulners.Bulletin{
			{ID: "other-product", AffectedSoftware: []vulners.AffectedSoftware{{Name: "other", Version: "1.0"}}},
			{ID: "other-version", AffectedSoftware: []vulners.AffectedSoftware{{Name: "pkg", Version: "2.0"}}},
			{ID: "missing-version", AffectedSoftware: []vulners.AffectedSoftware{{Name: "pkg"}}},
			{ID: "no-metadata"},
		}}, nil
	}}
	findings, err := NewMatcher(client, slog.Default()).Match(context.Background(), []model.Component{{Name: "pkg", Version: "1.0"}})
	if err != nil || len(findings) != 0 {
		t.Fatalf("got %v, %v; want no findings", findings, err)
	}
}

func TestBuildQuery_UntrustedBooleanWords(t *testing.T) {
	got := buildQuery(model.Component{Name: "x OR type:exploit", Version: "1.0"})
	want := `affectedSoftware.name:"x OR type:exploit"`
	if got != want {
		t.Fatalf("query = %q, want %q", got, want)
	}
}

func TestMatcher_RangeOnLaterSearchPage(t *testing.T) {
	calls := 0
	client := &mockClient{searchFn: func(_ context.Context, query string, limit, offset int) (*intel.SearchResult, error) {
		calls++
		if query != `affectedSoftware.name:"pkg"` || limit != 100 {
			t.Fatalf("unexpected query or page size: %q, %d", query, limit)
		}
		if offset == 0 {
			bulletins := make([]vulners.Bulletin, 100)
			for i := range bulletins {
				bulletins[i] = vulners.Bulletin{ID: fmt.Sprint(i), AffectedSoftware: []vulners.AffectedSoftware{{Name: "pkg", Version: "9.0"}}}
			}
			return &intel.SearchResult{Total: 101, Bulletins: bulletins}, nil
		}
		if offset != 100 {
			t.Fatalf("unexpected offset %d", offset)
		}
		return &intel.SearchResult{Total: 101, Bulletins: []vulners.Bulletin{{ID: "RANGE", AffectedSoftware: []vulners.AffectedSoftware{{Name: "pkg", Version: "2.0", Operator: "le"}}}}}, nil
	}}
	findings, err := NewMatcher(client, slog.Default()).Match(context.Background(), []model.Component{{Name: "pkg", Version: "1.10"}})
	if err != nil || len(findings) != 1 || findings[0].VulnID != "RANGE" || calls != 2 {
		t.Fatalf("range scan: %v, %v, calls=%d", findings, err, calls)
	}
}

func TestMatcher_RangeOrPaginationFailureReturnsNoPartialFindings(t *testing.T) {
	for _, failLookup := range []bool{false, true} {
		client := &mockClient{searchFn: func(_ context.Context, _ string, _, offset int) (*intel.SearchResult, error) {
			if offset == 0 {
				return &intel.SearchResult{Total: 2, Bulletins: []vulners.Bulletin{{ID: "FIRST", AffectedSoftware: []vulners.AffectedSoftware{{Name: "pkg", Version: "1.0"}}}}}, nil
			}
			if failLookup {
				return nil, fmt.Errorf("lookup failed")
			}
			return &intel.SearchResult{Total: 2, Bulletins: []vulners.Bulletin{{ID: "INVALID", AffectedSoftware: []vulners.AffectedSoftware{{Name: "pkg", Version: "release-final", Operator: "le"}}}}}, nil
		}}
		findings, err := NewMatcher(client, slog.Default()).Match(context.Background(), []model.Component{{Name: "pkg", Version: "1.0"}})
		if err == nil || len(findings) != 0 {
			t.Fatalf("partial scan must fail: %v, %v", findings, err)
		}
	}
}
