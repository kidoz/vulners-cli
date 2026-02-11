package intel

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"time"

	vulners "github.com/kidoz/go-vulners"
)

// VulnersClient implements the Client interface using go-vulners.
type VulnersClient struct {
	client *vulners.Client
	logger *slog.Logger
}

// Version is the CLI version injected by main.go for the HTTP user-agent.
var Version = "dev"

// Default HTTP timeout for API requests.
const defaultTimeout = 120 * time.Second

// allFields requests all useful Bulletin fields from the API.
var allFields = []string{
	"id", "title", "description", "type", "bulletinFamily",
	"cvss", "cvss2", "cvss3", "published", "modified",
	"href", "sourceHref", "sourceData", "cvelist",
	"epss", "affectedSoftware", "references",
	"ai", "reporter", "vulnStatus", "enchantments",
	"lastseen", "objectVersion",
}

// NewVulnersClient creates a new Vulners API client.
func NewVulnersClient(apiKey string, logger *slog.Logger) (*VulnersClient, error) {
	if apiKey == "" {
		return nil, fmt.Errorf("VULNERS_API_KEY is required")
	}

	c, err := vulners.NewClient(apiKey,
		vulners.WithTimeout(defaultTimeout),
		vulners.WithUserAgent("vulners-cli/"+Version),
	)
	if err != nil {
		return nil, fmt.Errorf("creating vulners client: %w", err)
	}

	return &VulnersClient{client: c, logger: logger}, nil
}

func (v *VulnersClient) Search(ctx context.Context, query string, limit, offset int) (*SearchResult, error) {
	v.logger.Debug("searching vulners", "query", query, "limit", limit, "offset", offset)

	opts := []vulners.SearchOption{
		vulners.WithLimit(limit),
		vulners.WithOffset(offset),
		vulners.WithFields(allFields...),
	}

	result, err := v.client.Search().SearchBulletins(ctx, query, opts...)
	if err != nil {
		return nil, fmt.Errorf("searching bulletins: %w", err)
	}

	return &SearchResult{
		Total:     result.Total,
		Bulletins: result.Bulletins,
	}, nil
}

func (v *VulnersClient) GetBulletin(ctx context.Context, id string) (*vulners.Bulletin, error) {
	v.logger.Debug("getting bulletin", "id", id)

	b, err := v.client.Search().GetBulletin(ctx, id, vulners.WithFields(allFields...))
	if err != nil {
		return nil, fmt.Errorf("getting bulletin %s: %w", id, err)
	}

	return b, nil
}

func (v *VulnersClient) SearchCPE(ctx context.Context, product, vendor string, limit int) (*vulners.CPESearchResult, error) {
	v.logger.Debug("searching CPE", "product", product, "vendor", vendor)

	opts := []vulners.CPEOption{
		vulners.WithCPESize(limit),
	}

	result, err := v.client.Misc().SearchCPE(ctx, product, vendor, opts...)
	if err != nil {
		return nil, fmt.Errorf("searching CPE: %w", err)
	}

	return result, nil
}

func (v *VulnersClient) LinuxAudit(ctx context.Context, osName, osVersion string, packages []string) (*vulners.AuditResult, error) {
	v.logger.Debug("linux audit", "os", osName, "version", osVersion, "packages", len(packages))

	result, err := v.client.Audit().LinuxAudit(ctx, osName, osVersion, packages)
	if err != nil {
		return nil, fmt.Errorf("linux audit: %w", err)
	}

	return result, nil
}

func (v *VulnersClient) KBAudit(ctx context.Context, os string, kbList []string) (*vulners.AuditResult, error) {
	v.logger.Debug("windows KB audit", "os", os, "kbs", len(kbList))

	result, err := v.client.Audit().KBAudit(ctx, os, kbList)
	if err != nil {
		return nil, fmt.Errorf("KB audit: %w", err)
	}

	return result, nil
}

func (v *VulnersClient) SBOMAudit(ctx context.Context, sbom io.Reader) (*vulners.SBOMAuditResult, error) {
	v.logger.Debug("SBOM audit")

	result, err := v.client.Audit().SBOMAudit(ctx, sbom)
	if err != nil {
		return nil, fmt.Errorf("SBOM audit: %w", err)
	}

	return result, nil
}

func (v *VulnersClient) FetchCollection(ctx context.Context, collType vulners.CollectionType) ([]vulners.Bulletin, error) {
	v.logger.Debug("fetching collection", "type", collType)

	bulletins, err := v.client.Archive().FetchCollection(ctx, collType)
	if err != nil {
		return nil, fmt.Errorf("fetching collection %s: %w", collType, err)
	}

	return bulletins, nil
}

func (v *VulnersClient) FetchCollectionUpdate(ctx context.Context, collType vulners.CollectionType, after time.Time) ([]vulners.Bulletin, error) {
	v.logger.Debug("fetching collection update", "type", collType, "after", after)

	bulletins, err := v.client.Archive().FetchCollectionUpdate(ctx, collType, after)
	if err != nil {
		return nil, fmt.Errorf("fetching collection update %s: %w", collType, err)
	}

	return bulletins, nil
}

func (v *VulnersClient) SearchExploits(ctx context.Context, query string, limit, offset int) (*SearchResult, error) {
	v.logger.Debug("searching exploits", "query", query, "limit", limit, "offset", offset)

	opts := []vulners.SearchOption{
		vulners.WithLimit(limit),
		vulners.WithOffset(offset),
		vulners.WithFields(allFields...),
	}

	result, err := v.client.Search().SearchExploits(ctx, query, opts...)
	if err != nil {
		return nil, fmt.Errorf("searching exploits: %w", err)
	}

	return &SearchResult{
		Total:     result.Total,
		Bulletins: result.Bulletins,
	}, nil
}

func (v *VulnersClient) GetMultipleBulletins(ctx context.Context, ids []string) (map[string]vulners.Bulletin, error) {
	v.logger.Debug("getting multiple bulletins", "count", len(ids))

	result, err := v.client.Search().GetMultipleBulletins(ctx, ids, vulners.WithFields(allFields...))
	if err != nil {
		return nil, fmt.Errorf("getting multiple bulletins: %w", err)
	}

	return result, nil
}

func (v *VulnersClient) GetBulletinReferences(ctx context.Context, id string) ([]string, error) {
	v.logger.Debug("getting bulletin references", "id", id)

	refs, err := v.client.Search().GetBulletinReferences(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("getting bulletin references %s: %w", id, err)
	}

	return refs, nil
}

func (v *VulnersClient) GetBulletinHistory(ctx context.Context, id string) ([]vulners.HistoryEntry, error) {
	v.logger.Debug("getting bulletin history", "id", id)

	history, err := v.client.Search().GetBulletinHistory(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("getting bulletin history %s: %w", id, err)
	}

	return history, nil
}

func (v *VulnersClient) HostAudit(ctx context.Context, osName, osVersion string, packages []vulners.AuditItem) (*vulners.AuditResult, error) {
	v.logger.Debug("host audit", "os", osName, "version", osVersion, "packages", len(packages))

	result, err := v.client.Audit().Host(ctx, osName, osVersion, packages)
	if err != nil {
		return nil, fmt.Errorf("host audit: %w", err)
	}

	return result, nil
}

func (v *VulnersClient) WinAudit(ctx context.Context, osName, osVersion string, kbList []string, software []vulners.WinAuditItem) (*vulners.AuditResult, error) {
	v.logger.Debug("windows audit", "os", osName, "version", osVersion, "kbs", len(kbList), "software", len(software))

	result, err := v.client.Audit().WinAudit(ctx, osName, osVersion, kbList, software)
	if err != nil {
		return nil, fmt.Errorf("windows audit: %w", err)
	}

	return result, nil
}

func (v *VulnersClient) GetAIScore(ctx context.Context, text string) (*vulners.AIScore, error) {
	v.logger.Debug("getting AI score")

	score, err := v.client.Misc().GetAIScore(ctx, text)
	if err != nil {
		return nil, fmt.Errorf("getting AI score: %w", err)
	}

	return score, nil
}

func (v *VulnersClient) MakeSTIXBundleByID(ctx context.Context, id string) (*vulners.StixBundle, error) {
	v.logger.Debug("making STIX bundle by ID", "id", id)

	bundle, err := v.client.Stix().MakeBundleByID(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("making STIX bundle for %s: %w", id, err)
	}

	return bundle, nil
}

func (v *VulnersClient) MakeSTIXBundleByCVE(ctx context.Context, cveID string) (*vulners.StixBundle, error) {
	v.logger.Debug("making STIX bundle by CVE", "cve", cveID)

	bundle, err := v.client.Stix().MakeBundleByCVE(ctx, cveID)
	if err != nil {
		return nil, fmt.Errorf("making STIX bundle for CVE %s: %w", cveID, err)
	}

	return bundle, nil
}

func (v *VulnersClient) QueryAutocomplete(ctx context.Context, query string) ([]string, error) {
	v.logger.Debug("query autocomplete", "query", query)

	suggestions, err := v.client.Misc().QueryAutocomplete(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("query autocomplete: %w", err)
	}

	return suggestions, nil
}

func (v *VulnersClient) GetSuggestion(ctx context.Context, fieldName string) ([]string, error) {
	v.logger.Debug("get suggestion", "field", fieldName)

	suggestions, err := v.client.Misc().GetSuggestion(ctx, fieldName)
	if err != nil {
		return nil, fmt.Errorf("get suggestion: %w", err)
	}

	return suggestions, nil
}

func (v *VulnersClient) VulnsSummaryReport(ctx context.Context, limit, offset int) (*vulners.VulnsSummary, error) {
	v.logger.Debug("vulns summary report", "limit", limit, "offset", offset)

	result, err := v.client.Report().VulnsSummaryReport(ctx,
		vulners.WithReportLimit(limit),
		vulners.WithReportOffset(offset),
	)
	if err != nil {
		return nil, fmt.Errorf("vulns summary report: %w", err)
	}
	return result, nil
}

func (v *VulnersClient) VulnsList(ctx context.Context, limit, offset int) ([]vulners.VulnItem, error) {
	v.logger.Debug("vulns list", "limit", limit, "offset", offset)

	result, err := v.client.Report().VulnsList(ctx,
		vulners.WithReportLimit(limit),
		vulners.WithReportOffset(offset),
	)
	if err != nil {
		return nil, fmt.Errorf("vulns list: %w", err)
	}
	return result, nil
}

func (v *VulnersClient) HostVulns(ctx context.Context, limit, offset int) ([]vulners.HostVuln, error) {
	v.logger.Debug("host vulns", "limit", limit, "offset", offset)

	result, err := v.client.Report().HostVulns(ctx,
		vulners.WithReportLimit(limit),
		vulners.WithReportOffset(offset),
	)
	if err != nil {
		return nil, fmt.Errorf("host vulns: %w", err)
	}
	return result, nil
}

func (v *VulnersClient) ScanList(ctx context.Context, limit, offset int) ([]vulners.ScanItem, error) {
	v.logger.Debug("scan list", "limit", limit, "offset", offset)

	result, err := v.client.Report().ScanList(ctx,
		vulners.WithReportLimit(limit),
		vulners.WithReportOffset(offset),
	)
	if err != nil {
		return nil, fmt.Errorf("scan list: %w", err)
	}
	return result, nil
}

func (v *VulnersClient) IPSummaryReport(ctx context.Context) (*vulners.IPSummary, error) {
	v.logger.Debug("IP summary report")

	result, err := v.client.Report().IPSummaryReport(ctx)
	if err != nil {
		return nil, fmt.Errorf("IP summary report: %w", err)
	}
	return result, nil
}
