// Package affected checks affected-product metadata shared by online and offline scans.
package affected

import (
	"fmt"
	"strings"

	versionutil "github.com/hashicorp/go-version"
	vulners "github.com/kidoz/go-vulners"
)

// Matches checks exact CPEs and named-product versions, including relational ranges.
// Empty versions are unknown; an explicit wildcard denotes all versions.
// Ranges use numeric, SemVer-like ordering. Unsupported versions fail the scan.
func Matches(b *vulners.Bulletin, name, version, cpe string) (bool, error) {
	for _, a := range b.AffectedSoftware {
		if cpe != "" && a.CPE == cpe {
			return true, nil
		}
		if name == "" || version == "" || !strings.EqualFold(strings.TrimSpace(a.Name), name) {
			continue
		}
		matches, err := matchesVersion(version, strings.TrimSpace(a.Version), a.Operator)
		if err != nil {
			return false, fmt.Errorf("matching bulletin %s for %s@%s: %w", b.ID, name, version, err)
		}
		if matches {
			return true, nil
		}
	}
	return false, nil
}

func matchesVersion(installed, boundary, operator string) (bool, error) {
	if boundary == "" {
		return false, nil
	}
	if boundary == "*" {
		return true, nil
	}
	operator = strings.ToLower(strings.TrimSpace(operator))
	switch operator {
	case "", "eq", "=", "==":
		return installed == boundary, nil
	case "lt", "<", "le", "<=", "gt", ">", "ge", ">=":
		cmp, err := compareVersions(installed, boundary)
		if err != nil {
			return false, err
		}
		return comparisonMatches(cmp, operator), nil
	default:
		return false, fmt.Errorf("unsupported affected-version operator %q", operator)
	}
}

func compareVersions(installed, boundary string) (int, error) {
	current, err := versionutil.NewVersion(installed)
	if err != nil {
		return 0, fmt.Errorf("unsupported installed version for range comparison: %w", err)
	}
	limit, err := versionutil.NewVersion(boundary)
	if err != nil {
		return 0, fmt.Errorf("unsupported advisory version for range comparison: %w", err)
	}
	return current.Compare(limit), nil
}

func comparisonMatches(cmp int, operator string) bool {
	switch operator {
	case "lt", "<":
		return cmp < 0
	case "le", "<=":
		return cmp <= 0
	case "gt", ">":
		return cmp > 0
	case "ge", ">=":
		return cmp >= 0
	default:
		return false
	}
}
