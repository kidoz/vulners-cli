package matcher

import (
	vulners "github.com/kidoz/go-vulners"
	"github.com/kidoz/vulners-cli/internal/model"
)

// BulletinToFinding converts a Vulners Bulletin into a Finding.
func BulletinToFinding(b *vulners.Bulletin, componentRef string) model.Finding {
	severity := "unknown"
	var cvss float64
	if b.CVSS3 != nil {
		cvss = b.CVSS3.Score
		severity = model.ScoreSeverity(cvss)
	} else if b.CVSS != nil {
		cvss = b.CVSS.Score
		severity = model.ScoreSeverity(cvss)
	}

	f := model.Finding{
		VulnID:       b.ID,
		Aliases:      b.CVEList,
		Severity:     severity,
		CVSS:         cvss,
		HasExploit:   b.Type == "exploit",
		ComponentRef: componentRef,
	}

	if len(b.References) > 0 {
		f.References = b.References
	} else if b.Href != "" {
		f.References = []string{b.Href}
	}
	if len(b.Epss) > 0 && b.Epss[0].Epss > 0 {
		v := b.Epss[0].Epss
		f.EPSS = &v
	}
	if b.AI != nil {
		f.AIScore = &b.AI.Value
	}
	return f
}
