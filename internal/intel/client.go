package intel

import (
	"context"
	"io"
	"time"

	vulners "github.com/kidoz/go-vulners"
)

// Client is the interface for vulnerability intelligence lookups.
type Client interface {
	Search(ctx context.Context, query string, limit, offset int) (*SearchResult, error)
	SearchExploits(ctx context.Context, query string, limit, offset int) (*SearchResult, error)
	GetBulletin(ctx context.Context, id string) (*vulners.Bulletin, error)
	GetMultipleBulletins(ctx context.Context, ids []string) (map[string]vulners.Bulletin, error)
	GetBulletinReferences(ctx context.Context, id string) ([]string, error)
	GetBulletinHistory(ctx context.Context, id string) ([]vulners.HistoryEntry, error)
	SearchCPE(ctx context.Context, product, vendor string, limit int) (*vulners.CPESearchResult, error)
	LinuxAudit(ctx context.Context, osName, osVersion string, packages []string) (*vulners.AuditResult, error)
	KBAudit(ctx context.Context, os string, kbList []string) (*vulners.AuditResult, error)
	HostAudit(ctx context.Context, osName, osVersion string, packages []vulners.AuditItem) (*vulners.AuditResult, error)
	WinAudit(ctx context.Context, osName, osVersion string, kbList []string, software []vulners.WinAuditItem) (*vulners.AuditResult, error)
	SBOMAudit(ctx context.Context, sbom io.Reader) (*vulners.SBOMAuditResult, error)
	FetchCollection(ctx context.Context, collType vulners.CollectionType) ([]vulners.Bulletin, error)
	FetchCollectionUpdate(ctx context.Context, collType vulners.CollectionType, after time.Time) ([]vulners.Bulletin, error)
	GetAIScore(ctx context.Context, text string) (*vulners.AIScore, error)
	MakeSTIXBundleByID(ctx context.Context, id string) (*vulners.StixBundle, error)
	MakeSTIXBundleByCVE(ctx context.Context, cveID string) (*vulners.StixBundle, error)
}

// SearchResult wraps the Vulners search response.
type SearchResult struct {
	Total     int                `json:"total"`
	Bulletins []vulners.Bulletin `json:"bulletins"`
}
