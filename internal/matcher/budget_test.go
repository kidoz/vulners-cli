package matcher

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"testing"

	vulners "github.com/kidoz/go-vulners"
	"github.com/kidoz/vulners-cli/internal/intel"
	"github.com/kidoz/vulners-cli/internal/model"
	"github.com/kidoz/vulners-cli/internal/scanbudget"
)

func TestMatcherComponentBudgetBeforeAPI(t *testing.T) {
	client := &mockClient{searchFn: func(context.Context, string, int, int) (*intel.SearchResult, error) {
		t.Fatal("API called for oversized inventory")
		return nil, nil
	}}
	findings, err := NewMatcher(client, slog.Default()).Match(context.Background(), make([]model.Component, scanbudget.MaxComponents+1))
	if !errors.Is(err, scanbudget.ErrExceeded) || findings != nil {
		t.Fatalf("expected component-budget failure without findings: %v, %v", findings, err)
	}
}

func TestMatcherRequestBudget(t *testing.T) {
	for _, pagination := range []bool{false, true} {
		calls := 0
		client := &mockClient{searchFn: func(_ context.Context, _ string, _, _ int) (*intel.SearchResult, error) {
			calls++
			result := &intel.SearchResult{Total: 1, Bulletins: []vulners.Bulletin{{ID: fmt.Sprint(calls), AffectedSoftware: []vulners.AffectedSoftware{{Name: "pkg", Version: "1.0"}}}}}
			if pagination {
				result.Total = scanbudget.MaxSearchRequests + 1
			}
			return result, nil
		}}
		components := []model.Component{{Name: "pkg", Version: "1.0"}}
		if !pagination {
			components = make([]model.Component, scanbudget.MaxSearchRequests+1)
			for i := range components {
				components[i] = model.Component{Name: "pkg", Version: "1.0"}
			}
		}
		findings, err := NewMatcher(client, slog.Default()).Match(context.Background(), components)
		if !errors.Is(err, scanbudget.ErrExceeded) || findings != nil || calls != scanbudget.MaxSearchRequests {
			t.Fatalf("pagination=%v: findings=%d, error=%v, requests=%d", pagination, len(findings), err, calls)
		}
	}
}
