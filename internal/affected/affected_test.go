package affected

import (
	"testing"

	vulners "github.com/kidoz/go-vulners"
)

func TestMatches(t *testing.T) {
	cases := []struct {
		name  string
		entry vulners.AffectedSoftware
		want  bool
	}{
		{"exact", vulners.AffectedSoftware{Name: "Pkg", Version: "1.0"}, true},
		{"explicit wildcard", vulners.AffectedSoftware{Name: "pkg", Version: "*"}, true},
		{"unknown version", vulners.AffectedSoftware{Name: "pkg"}, false},
		{"different version", vulners.AffectedSoftware{Name: "pkg", Version: "2.0"}, false},
		{"different product", vulners.AffectedSoftware{Name: "other", Version: "1.0"}, false},
		{"exclusive boundary", vulners.AffectedSoftware{Name: "pkg", Version: "1.0", Operator: "lt"}, false},
		{"inclusive boundary", vulners.AffectedSoftware{Name: "pkg", Version: "1.0", Operator: "le"}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b := &vulners.Bulletin{AffectedSoftware: []vulners.AffectedSoftware{tc.entry}}
			if got, err := Matches(b, "pkg", "1.0", ""); err != nil || got != tc.want {
				t.Fatalf("match = %v, want %v", got, tc.want)
			}
		})
	}
	b := &vulners.Bulletin{AffectedSoftware: []vulners.AffectedSoftware{{CPE: "cpe:/a:vendor:product:1.0"}}}
	if got, err := Matches(b, "", "", "cpe:/a:vendor:product:1.0"); err != nil || !got {
		t.Fatal("exact CPE must match")
	}
	if got, err := Matches(b, "", "", "cpe:/a:vendor:product:2.0"); err != nil || got {
		t.Fatal("different CPE must not match")
	}
}

func TestMatches_RelationalVersions(t *testing.T) {
	for _, operator := range []string{"le", "<=", "lt", "<", "ge", ">=", "gt", ">"} {
		for _, installed := range []string{"0.9", "1.0", "1.1", "1.10"} {
			t.Run(operator+installed, func(t *testing.T) {
				want := false
				switch operator {
				case "le", "<=":
					want = installed == "0.9" || installed == "1.0"
				case "lt", "<":
					want = installed == "0.9"
				case "ge", ">=":
					want = installed != "0.9"
				case "gt", ">":
					want = installed != "0.9" && installed != "1.0"
				}
				b := &vulners.Bulletin{AffectedSoftware: []vulners.AffectedSoftware{{Name: "pkg", Version: "1.0", Operator: operator}}}
				if got, err := Matches(b, "pkg", installed, ""); err != nil || got != want {
					t.Fatalf("%s %s 1.0: got %v, want %v", installed, operator, got, want)
				}
			})
		}
	}
}

func TestMatches_OrderedVersionFormats(t *testing.T) {
	cases := []struct {
		installed, boundary, operator string
		want                          bool
	}{
		{"1.9", "1.10", "lt", true},
		{"1.10", "1.9", "le", false},
		{"1.0.0-rc.1", "1.0.0", "lt", true},
		{"1.0.0", "1.0.0-rc.1", "gt", true},
		{"v1.0.0", "1.0", "le", true},
		{"1.0.0+build.1", "1.0.0+build.2", "ge", true},
	}
	for _, tc := range cases {
		b := &vulners.Bulletin{AffectedSoftware: []vulners.AffectedSoftware{{Name: "pkg", Version: tc.boundary, Operator: tc.operator}}}
		got, err := Matches(b, "pkg", tc.installed, "")
		if err != nil || got != tc.want {
			t.Errorf("%s %s %s = %v, %v; want %v", tc.installed, tc.operator, tc.boundary, got, err, tc.want)
		}
	}
}

func TestMatches_UnsupportedRangesReturnError(t *testing.T) {
	for _, tc := range []struct{ installed, boundary, operator string }{
		{"1:2.0", "3.0", "lt"},
		{"1.0", "release-final", "le"},
		{"1.0", "2.0", "mystery"},
	} {
		b := &vulners.Bulletin{AffectedSoftware: []vulners.AffectedSoftware{{Name: "pkg", Version: tc.boundary, Operator: tc.operator}}}
		got, err := Matches(b, "pkg", tc.installed, "")
		if err == nil || got {
			t.Errorf("unsupported range must fail: %s %s %s = %v, %v", tc.installed, tc.operator, tc.boundary, got, err)
		}
	}
}
