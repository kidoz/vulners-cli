package cmd

import (
	"context"
	"io"
	"time"

	vulners "github.com/kidoz/go-vulners"
	"github.com/kidoz/vulners-cli/internal/intel"
)

// mockIntelClient implements intel.Client with configurable function fields.
type mockIntelClient struct {
	searchFn                func(ctx context.Context, query string, limit, offset int) (*intel.SearchResult, error)
	searchExploitsFn        func(ctx context.Context, query string, limit, offset int) (*intel.SearchResult, error)
	getBulletinFn           func(ctx context.Context, id string) (*vulners.Bulletin, error)
	getMultipleBulletinsFn  func(ctx context.Context, ids []string) (map[string]vulners.Bulletin, error)
	getBulletinRefsFn       func(ctx context.Context, id string) ([]string, error)
	getBulletinHistoryFn    func(ctx context.Context, id string) ([]vulners.HistoryEntry, error)
	searchCPEFn             func(ctx context.Context, product, vendor string, limit int) (*vulners.CPESearchResult, error)
	linuxAuditFn            func(ctx context.Context, osName, osVersion string, packages []string) (*vulners.AuditResult, error)
	kbAuditFn               func(ctx context.Context, os string, kbList []string) (*vulners.AuditResult, error)
	hostAuditFn             func(ctx context.Context, osName, osVersion string, packages []vulners.AuditItem) (*vulners.AuditResult, error)
	winAuditFn              func(ctx context.Context, osName, osVersion string, kbList []string, software []vulners.WinAuditItem) (*vulners.AuditResult, error)
	sbomAuditFn             func(ctx context.Context, sbom io.Reader) (*vulners.SBOMAuditResult, error)
	fetchCollectionFn       func(ctx context.Context, collType vulners.CollectionType) ([]vulners.Bulletin, error)
	fetchCollectionUpdateFn func(ctx context.Context, collType vulners.CollectionType, after time.Time) ([]vulners.Bulletin, error)
	getAIScoreFn            func(ctx context.Context, text string) (*vulners.AIScore, error)
	makeSTIXBundleByIDFn    func(ctx context.Context, id string) (*vulners.StixBundle, error)
	makeSTIXBundleByCVEFn   func(ctx context.Context, cveID string) (*vulners.StixBundle, error)
	queryAutocompleteFn     func(ctx context.Context, query string) ([]string, error)
}

func (m *mockIntelClient) Search(ctx context.Context, query string, limit, offset int) (*intel.SearchResult, error) {
	if m.searchFn != nil {
		return m.searchFn(ctx, query, limit, offset)
	}
	return &intel.SearchResult{}, nil
}

func (m *mockIntelClient) SearchExploits(ctx context.Context, query string, limit, offset int) (*intel.SearchResult, error) {
	if m.searchExploitsFn != nil {
		return m.searchExploitsFn(ctx, query, limit, offset)
	}
	return &intel.SearchResult{}, nil
}

func (m *mockIntelClient) GetBulletin(ctx context.Context, id string) (*vulners.Bulletin, error) {
	if m.getBulletinFn != nil {
		return m.getBulletinFn(ctx, id)
	}
	return &vulners.Bulletin{ID: "TEST"}, nil
}

func (m *mockIntelClient) GetMultipleBulletins(ctx context.Context, ids []string) (map[string]vulners.Bulletin, error) {
	if m.getMultipleBulletinsFn != nil {
		return m.getMultipleBulletinsFn(ctx, ids)
	}
	return nil, nil
}

func (m *mockIntelClient) GetBulletinReferences(ctx context.Context, id string) ([]string, error) {
	if m.getBulletinRefsFn != nil {
		return m.getBulletinRefsFn(ctx, id)
	}
	return nil, nil
}

func (m *mockIntelClient) GetBulletinHistory(ctx context.Context, id string) ([]vulners.HistoryEntry, error) {
	if m.getBulletinHistoryFn != nil {
		return m.getBulletinHistoryFn(ctx, id)
	}
	return nil, nil
}

func (m *mockIntelClient) SearchCPE(ctx context.Context, product, vendor string, limit int) (*vulners.CPESearchResult, error) {
	if m.searchCPEFn != nil {
		return m.searchCPEFn(ctx, product, vendor, limit)
	}
	return &vulners.CPESearchResult{}, nil
}

func (m *mockIntelClient) LinuxAudit(ctx context.Context, osName, osVersion string, packages []string) (*vulners.AuditResult, error) {
	if m.linuxAuditFn != nil {
		return m.linuxAuditFn(ctx, osName, osVersion, packages)
	}
	return &vulners.AuditResult{}, nil
}

func (m *mockIntelClient) KBAudit(ctx context.Context, os string, kbList []string) (*vulners.AuditResult, error) {
	if m.kbAuditFn != nil {
		return m.kbAuditFn(ctx, os, kbList)
	}
	return &vulners.AuditResult{}, nil
}

func (m *mockIntelClient) HostAudit(ctx context.Context, osName, osVersion string, packages []vulners.AuditItem) (*vulners.AuditResult, error) {
	if m.hostAuditFn != nil {
		return m.hostAuditFn(ctx, osName, osVersion, packages)
	}
	return &vulners.AuditResult{}, nil
}

func (m *mockIntelClient) WinAudit(ctx context.Context, osName, osVersion string, kbList []string, software []vulners.WinAuditItem) (*vulners.AuditResult, error) {
	if m.winAuditFn != nil {
		return m.winAuditFn(ctx, osName, osVersion, kbList, software)
	}
	return &vulners.AuditResult{}, nil
}

func (m *mockIntelClient) SBOMAudit(ctx context.Context, sbom io.Reader) (*vulners.SBOMAuditResult, error) {
	if m.sbomAuditFn != nil {
		return m.sbomAuditFn(ctx, sbom)
	}
	return nil, nil
}

func (m *mockIntelClient) FetchCollection(ctx context.Context, collType vulners.CollectionType) ([]vulners.Bulletin, error) {
	if m.fetchCollectionFn != nil {
		return m.fetchCollectionFn(ctx, collType)
	}
	return nil, nil
}

func (m *mockIntelClient) FetchCollectionUpdate(ctx context.Context, collType vulners.CollectionType, after time.Time) ([]vulners.Bulletin, error) {
	if m.fetchCollectionUpdateFn != nil {
		return m.fetchCollectionUpdateFn(ctx, collType, after)
	}
	return nil, nil
}

func (m *mockIntelClient) GetAIScore(ctx context.Context, text string) (*vulners.AIScore, error) {
	if m.getAIScoreFn != nil {
		return m.getAIScoreFn(ctx, text)
	}
	return nil, nil
}

func (m *mockIntelClient) MakeSTIXBundleByID(ctx context.Context, id string) (*vulners.StixBundle, error) {
	if m.makeSTIXBundleByIDFn != nil {
		return m.makeSTIXBundleByIDFn(ctx, id)
	}
	return &vulners.StixBundle{}, nil
}

func (m *mockIntelClient) MakeSTIXBundleByCVE(ctx context.Context, cveID string) (*vulners.StixBundle, error) {
	if m.makeSTIXBundleByCVEFn != nil {
		return m.makeSTIXBundleByCVEFn(ctx, cveID)
	}
	return &vulners.StixBundle{}, nil
}

func (m *mockIntelClient) QueryAutocomplete(ctx context.Context, query string) ([]string, error) {
	if m.queryAutocompleteFn != nil {
		return m.queryAutocompleteFn(ctx, query)
	}
	return nil, nil
}
