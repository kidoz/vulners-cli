package matcher

import (
	"testing"

	vulners "github.com/kidoz/go-vulners"
)

func TestBulletinToFinding_CVSSSelection(t *testing.T) {
	tests := []struct {
		name     string
		bulletin vulners.Bulletin
		wantCVSS float64
		wantSev  string
	}{
		{
			name: "empty cvss3 falls back to cvss",
			bulletin: vulners.Bulletin{
				CVSS3: &vulners.CVSS3{},
				CVSS:  &vulners.CVSS{Score: 7.5},
			},
			wantCVSS: 7.5,
			wantSev:  "high",
		},
		{
			name: "valid zero cvss3 does not fall through",
			bulletin: vulners.Bulletin{
				CVSS3: &vulners.CVSS3{CVSS: vulners.CVSS{Score: 0, Vector: "CVSS:3.1/AV:N/AC:H"}},
				CVSS:  &vulners.CVSS{Score: 7.5},
			},
			wantCVSS: 0,
			wantSev:  "none",
		},
		{
			name: "cvss4 used when cvss3 is empty",
			bulletin: vulners.Bulletin{
				CVSS3: &vulners.CVSS3{},
				CVSS4: &vulners.CVSS{Score: 9.1},
			},
			wantCVSS: 9.1,
			wantSev:  "critical",
		},
		{
			name: "populated cvss3 takes priority",
			bulletin: vulners.Bulletin{
				CVSS3: &vulners.CVSS3{CVSS: vulners.CVSS{Score: 5.0}},
				CVSS:  &vulners.CVSS{Score: 9.8},
			},
			wantCVSS: 5.0,
			wantSev:  "medium",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := BulletinToFinding(&tt.bulletin, "pkg@1.0")
			if f.CVSS != tt.wantCVSS {
				t.Errorf("CVSS = %v, want %v", f.CVSS, tt.wantCVSS)
			}
			if f.Severity != tt.wantSev {
				t.Errorf("Severity = %q, want %q", f.Severity, tt.wantSev)
			}
		})
	}
}
