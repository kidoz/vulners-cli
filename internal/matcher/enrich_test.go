package matcher

import (
	"context"
	"fmt"
	"log/slog"
	"testing"

	vulners "github.com/kidoz/go-vulners"
	"github.com/kidoz/vulners-cli/internal/model"
)

func TestEnricher_Enrich_BatchFetch(t *testing.T) {
	client := &mockClient{
		getMultipleFn: func(_ context.Context, ids []string) (map[string]vulners.Bulletin, error) {
			result := make(map[string]vulners.Bulletin)
			for _, id := range ids {
				result[id] = vulners.Bulletin{
					ID:   id,
					CVSS: &vulners.CVSS{Score: 9.8},
					Type: "cve",
					Href: "https://vulners.com/cve/" + id,
				}
			}
			return result, nil
		},
	}

	e := NewEnricher(client, slog.Default())
	findings := []model.Finding{
		{VulnID: "CVE-2021-44228", Severity: "unknown"},
		{VulnID: "CVE-2023-1234", Severity: "unknown"},
	}

	result := e.Enrich(context.Background(), findings)
	if len(result) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(result))
	}
	for _, f := range result {
		if f.CVSS != 9.8 {
			t.Errorf("expected CVSS 9.8, got %f", f.CVSS)
		}
		if f.Severity != "critical" {
			t.Errorf("expected severity critical, got %q", f.Severity)
		}
	}
}

func TestEnricher_Enrich_FallbackToIndividual(t *testing.T) {
	client := &mockClient{
		getMultipleFn: func(context.Context, []string) (map[string]vulners.Bulletin, error) {
			return nil, fmt.Errorf("batch not supported")
		},
		getBulletinFn: func(_ context.Context, id string) (*vulners.Bulletin, error) {
			return &vulners.Bulletin{
				ID:   id,
				CVSS: &vulners.CVSS{Score: 7.5},
				Type: "cve",
			}, nil
		},
	}

	e := NewEnricher(client, slog.Default())
	findings := []model.Finding{
		{VulnID: "CVE-2021-44228"},
	}

	result := e.Enrich(context.Background(), findings)
	if result[0].CVSS != 7.5 {
		t.Errorf("expected CVSS 7.5, got %f", result[0].CVSS)
	}
}

func TestEnricher_Enrich_NilIntel(t *testing.T) {
	e := NewEnricher(nil, slog.Default())
	findings := []model.Finding{{VulnID: "CVE-2021-44228"}}
	result := e.Enrich(context.Background(), findings)
	if len(result) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(result))
	}
	if result[0].CVSS != 0 {
		t.Errorf("expected CVSS 0 (unenriched), got %f", result[0].CVSS)
	}
}

func TestEnricher_Enrich_EmptyFindings(t *testing.T) {
	e := NewEnricher(&mockClient{}, slog.Default())
	result := e.Enrich(context.Background(), nil)
	if result != nil {
		t.Errorf("expected nil, got %v", result)
	}
}

func TestEnricher_WithAIScore(t *testing.T) {
	aiScore := 8.5
	client := &mockClient{
		getMultipleFn: func(context.Context, []string) (map[string]vulners.Bulletin, error) {
			return map[string]vulners.Bulletin{
				"CVE-2021-44228": {ID: "CVE-2021-44228", CVSS: &vulners.CVSS{Score: 10.0}},
			}, nil
		},
		getAIScoreFn: func(_ context.Context, _ string) (*vulners.AIScore, error) {
			return &vulners.AIScore{Value: aiScore}, nil
		},
	}

	e := NewEnricher(client, slog.Default()).WithAIScore(true)
	findings := []model.Finding{
		{VulnID: "CVE-2021-44228"},
	}

	result := e.Enrich(context.Background(), findings)
	if result[0].AIScore == nil {
		t.Fatal("expected AIScore to be set")
	}
	if *result[0].AIScore != aiScore {
		t.Errorf("expected AIScore %f, got %f", aiScore, *result[0].AIScore)
	}
}

func TestEnricher_AIScore_NilResponse(t *testing.T) {
	client := &mockClient{
		getMultipleFn: func(context.Context, []string) (map[string]vulners.Bulletin, error) {
			return map[string]vulners.Bulletin{
				"CVE-2021-44228": {ID: "CVE-2021-44228"},
			}, nil
		},
		getAIScoreFn: func(context.Context, string) (*vulners.AIScore, error) {
			return nil, nil // nil response, no error
		},
	}

	e := NewEnricher(client, slog.Default()).WithAIScore(true)
	findings := []model.Finding{{VulnID: "CVE-2021-44228"}}
	result := e.Enrich(context.Background(), findings)
	if result[0].AIScore != nil {
		t.Error("expected AIScore to remain nil for nil response")
	}
}

func TestEnrichFinding_ExploitType(t *testing.T) {
	f := model.Finding{VulnID: "EDB-12345"}
	b := vulners.Bulletin{
		ID:   "EDB-12345",
		Type: "exploit",
		CVSS: &vulners.CVSS{Score: 7.0},
	}

	enrichFinding(&f, &b)
	if !f.HasExploit {
		t.Error("expected HasExploit to be true for exploit type")
	}
	if f.Severity != "high" {
		t.Errorf("expected severity high, got %q", f.Severity)
	}
}

func TestEnrichFinding_WithEPSS(t *testing.T) {
	f := model.Finding{VulnID: "CVE-2021-44228"}
	b := vulners.Bulletin{
		ID: "CVE-2021-44228",
		Epss: []vulners.Epss{
			{Epss: 0.97},
		},
	}

	enrichFinding(&f, &b)
	if f.EPSS == nil {
		t.Fatal("expected EPSS to be set")
	}
	if *f.EPSS != 0.97 {
		t.Errorf("expected EPSS 0.97, got %f", *f.EPSS)
	}
}

func TestEnrichFinding_WithAI(t *testing.T) {
	f := model.Finding{VulnID: "CVE-2021-44228"}
	b := vulners.Bulletin{
		ID: "CVE-2021-44228",
		AI: &vulners.AIScore{Value: 9.0},
	}

	enrichFinding(&f, &b)
	if f.AIScore == nil {
		t.Fatal("expected AIScore to be set")
	}
	if *f.AIScore != 9.0 {
		t.Errorf("expected AIScore 9.0, got %f", *f.AIScore)
	}
}
