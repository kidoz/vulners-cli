package matcher

import (
	vulners "github.com/kidoz/go-vulners"
	"github.com/kidoz/vulners-cli/internal/model"
)

// BulletinToFinding converts a Vulners Bulletin into a Finding.
func BulletinToFinding(b *vulners.Bulletin, componentRef string) model.Finding {
	severity := "unknown"
	cvss, hasScore := bestCVSS(b)
	if hasScore {
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

// bestCVSS returns the most specific non-empty CVSS score. The API often
// returns an empty cvss3 object alongside a populated cvss object.
func bestCVSS(b *vulners.Bulletin) (float64, bool) {
	candidates := []*vulners.CVSS{
		cvss3Score(b.CVSS3),
		b.CVSS4,
		b.CVSS,
	}
	for _, c := range candidates {
		if !hasCVSSData(c) {
			continue
		}
		return c.Score, true
	}
	return 0, false
}

func cvss3Score(c *vulners.CVSS3) *vulners.CVSS {
	if c == nil {
		return nil
	}
	return &c.CVSS
}

func hasCVSSData(c *vulners.CVSS) bool {
	return c != nil && (c.Score > 0 || c.Vector != "" || c.Severity != "")
}
