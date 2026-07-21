package host

import (
	"reflect"
	"testing"

	vulners "github.com/kidoz/go-vulners"
)

func TestNormalizeWindowsOS(t *testing.T) {
	tests := []struct {
		name        string
		caption     string
		buildNumber string
		want        string
	}{
		// Windows 10 / 11 disambiguation by build number.
		{"10 build 19045", "Microsoft Windows 10 Pro", "10.0.19045", "Windows 10"},
		{"11 build 22631", "Microsoft Windows 10 Pro", "10.0.22631", "Windows 11"},
		{"11 plain build 22000", "Microsoft Windows 11 Home", "22000", "Windows 11"},
		{"10 plain build 18362", "Windows 10 Home", "18362", "Windows 10"},
		{"10 no build number", "Microsoft Windows 10 Pro", "", "Windows 10"},

		// Windows Server: year and R2 revision retained, edition dropped.
		{"Server 2012", "Microsoft Windows Server 2012 Standard", "6.2.9200", "Windows Server 2012"},
		{"Server 2012 R2", "Microsoft Windows Server 2012 R2 Datacenter", "6.3.9600", "Windows Server 2012 R2"},
		{"Server 2008 R2 lowercase r2", "Microsoft Windows Server 2008 r2 Enterprise", "6.1.7601", "Windows Server 2008 R2"},
		{"Server 2016", "Microsoft Windows Server 2016 Standard", "10.0.14393", "Windows Server 2016"},
		{"Server 2019 Datacenter", "Microsoft Windows Server 2019 Datacenter", "10.0.17763", "Windows Server 2019"},
		{"Server 2022", "Microsoft Windows Server 2022 Standard", "10.0.20348", "Windows Server 2022"},
		{"Server 2025", "Microsoft Windows Server 2025 Datacenter", "10.0.26100", "Windows Server 2025"},

		// Legacy client SKUs.
		{"8.1", "Microsoft Windows 8.1 Pro", "6.3.9600", "Windows 8.1"},
		{"7", "Microsoft Windows 7 Ultimate", "6.1.7601", "Windows 7"},
		{"8", "Microsoft Windows 8 Enterprise", "6.2.9200", "Windows 8"},
		{"Vista", "Microsoft Windows Vista Ultimate", "6.0.6002", "Windows Vista"},
		{"XP", "Microsoft Windows XP Professional", "5.1.2600", "Windows XP"},

		// Edge cases.
		{"empty caption", "", "10.0.19045", "Windows"},
		{"unknown caption", "Unknown OS", "10.0.19045", "Windows"},
		{"lowercase microsoft prefix", "microsoft windows 10 pro", "10.0.19045", "Windows 10"},
		{"lowercase vista", "microsoft windows vista business", "6.0.6000", "Windows Vista"},
		{"lowercase xp", "microsoft windows xp professional", "5.1.2600", "Windows XP"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := NormalizeWindowsOS(tc.caption, tc.buildNumber)
			if got != tc.want {
				t.Errorf("NormalizeWindowsOS(%q, %q) = %q, want %q", tc.caption, tc.buildNumber, got, tc.want)
			}
		})
	}
}

func TestParseWindowsBuild(t *testing.T) {
	tests := []struct {
		in   string
		want int
	}{
		{"10.0.22631", 22631},
		{"22631", 22631},
		{"", 0},
		{"not-a-number", 0},
		{"10.0", 0}, // last segment is "0" => parsed as 0
	}
	for _, tc := range tests {
		got := parseWindowsBuild(tc.in)
		if got != tc.want {
			t.Errorf("parseWindowsBuild(%q) = %d, want %d", tc.in, got, tc.want)
		}
	}
}

func TestParseWindowsSoftware(t *testing.T) {
	lines := []string{
		"Mozilla Firefox\t118.0",
		"  Git\t2.42.0  ",
		"NameOnly",
		"",
		"   ",
		"\t  ", // empty after trim
	}
	expected := []vulners.WinAuditItem{
		{Software: "Mozilla Firefox", Version: "118.0"},
		{Software: "Git", Version: "2.42.0"},
		{Software: "NameOnly", Version: ""},
	}
	got := ParseWindowsSoftware(lines)
	if !reflect.DeepEqual(got, expected) {
		t.Errorf("ParseWindowsSoftware() = %+v, want %+v", got, expected)
	}
}
