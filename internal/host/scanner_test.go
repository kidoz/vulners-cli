package host

import (
	"context"
	"fmt"
	"reflect"
	"testing"

	vulners "github.com/kidoz/go-vulners"
)

type mockExecutor struct {
	responses map[string]string
	errors    map[string]error
}

func (m *mockExecutor) Execute(ctx context.Context, cmd string) (string, error) {
	if err, ok := m.errors[cmd]; ok {
		return "", err
	}
	if resp, ok := m.responses[cmd]; ok {
		return resp, nil
	}
	return "", fmt.Errorf("unexpected command: %s", cmd)
}

func (m *mockExecutor) Close() error {
	return nil
}

func TestScanner_DetectOS_Linux(t *testing.T) {
	mock := &mockExecutor{
		responses: map[string]string{
			"uname -s":            "Linux",
			"cat /etc/os-release": "ID=ubuntu\nVERSION_ID=\"22.04\"\nID_LIKE=debian",
		},
	}
	scanner := NewScanner(mock)
	info, err := scanner.DetectOS(context.Background())
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	expected := &OSInfo{Family: FamilyDeb, Distro: "ubuntu", Version: "22.04"}
	if !reflect.DeepEqual(info, expected) {
		t.Errorf("expected %+v, got %+v", expected, info)
	}
}

func TestScanner_DetectOS_Windows(t *testing.T) {
	mock := &mockExecutor{
		responses: map[string]string{
			"Get-CimInstance Win32_OperatingSystem | Select-Object Caption,BuildNumber | ConvertTo-Csv -NoTypeInformation": "\"Caption\",\"BuildNumber\"\r\n\"Microsoft Windows 10 Pro\",\"19045\"",
		},
		errors: map[string]error{
			"uname -s": fmt.Errorf("command not found"),
		},
	}
	scanner := NewScanner(mock)
	info, err := scanner.DetectOS(context.Background())
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	expected := &OSInfo{Family: FamilyWindows, OSName: "Microsoft Windows 10 Pro", BuildNumber: "19045"}
	if !reflect.DeepEqual(info, expected) {
		t.Errorf("expected %+v, got %+v", expected, info)
	}
}

func TestScanner_DetectOS_Windows_CaptionFallback(t *testing.T) {
	// CSV query unavailable; falls back to the plain Caption query.
	mock := &mockExecutor{
		responses: map[string]string{
			"(Get-CimInstance Win32_OperatingSystem).Caption": "Microsoft Windows Server 2019 Datacenter",
		},
		errors: map[string]error{
			"uname -s": fmt.Errorf("command not found"),
			"Get-CimInstance Win32_OperatingSystem | Select-Object Caption,BuildNumber | ConvertTo-Csv -NoTypeInformation": fmt.Errorf("command not found"),
		},
	}
	scanner := NewScanner(mock)
	info, err := scanner.DetectOS(context.Background())
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	expected := &OSInfo{Family: FamilyWindows, OSName: "Microsoft Windows Server 2019 Datacenter"}
	if !reflect.DeepEqual(info, expected) {
		t.Errorf("expected %+v, got %+v", expected, info)
	}
}

func TestParseWindowsOSCSV(t *testing.T) {
	cases := []struct {
		name        string
		output      string
		wantCaption string
		wantBuild   string
	}{
		{
			name:        "standard",
			output:      "\"Caption\",\"BuildNumber\"\r\n\"Microsoft Windows 10 Pro\",\"19045\"",
			wantCaption: "Microsoft Windows 10 Pro",
			wantBuild:   "19045",
		},
		{
			name:        "windows 11",
			output:      "\"Caption\",\"BuildNumber\"\n\"Microsoft Windows 10 Pro\",\"22631\"",
			wantCaption: "Microsoft Windows 10 Pro",
			wantBuild:   "22631",
		},
		{
			name:        "empty",
			output:      "",
			wantCaption: "",
			wantBuild:   "",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cap, build := parseWindowsOSCSV(tc.output)
			if cap != tc.wantCaption || build != tc.wantBuild {
				t.Errorf("parseWindowsOSCSV() = (%q, %q), want (%q, %q)", cap, build, tc.wantCaption, tc.wantBuild)
			}
		})
	}
}

func TestScanner_GatherPackages_Debian(t *testing.T) {
	mock := &mockExecutor{
		responses: map[string]string{
			"dpkg-query -W -f='${Package} ${Version} ${Architecture}\\n'": "libc6 2.35-0ubuntu3 amd64\ncurl 7.81.0-1ubuntu1.16 amd64",
		},
	}
	scanner := NewScanner(mock)
	info := &OSInfo{Family: FamilyDeb}

	packages, err := scanner.GatherPackages(context.Background(), info)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	expected := []string{"libc6 2.35-0ubuntu3 amd64", "curl 7.81.0-1ubuntu1.16 amd64"}
	if !reflect.DeepEqual(packages, expected) {
		t.Errorf("expected %v, got %v", expected, packages)
	}
}

func TestScanner_GatherWindows_GetPackage(t *testing.T) {
	mock := &mockExecutor{
		responses: map[string]string{
			winKBCmd:                 "KB5001\r\nKB5022",
			winSoftwareGetPackageCmd: "Git\t2.42.0\r\nMozilla Firefox\t118.0",
		},
	}
	scanner := NewScanner(mock)
	info := &OSInfo{Family: FamilyWindows}

	kbs, software, err := scanner.GatherWindows(context.Background(), info)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if !reflect.DeepEqual(kbs, []string{"KB5001", "KB5022"}) {
		t.Errorf("kbs = %v", kbs)
	}
	wantSoftware := []vulners.WinAuditItem{
		{Software: "Git", Version: "2.42.0"},
		{Software: "Mozilla Firefox", Version: "118.0"},
	}
	if !reflect.DeepEqual(software, wantSoftware) {
		t.Errorf("software = %+v, want %+v", software, wantSoftware)
	}
}

func TestScanner_GatherWindows_RegistryFallback(t *testing.T) {
	mock := &mockExecutor{
		responses: map[string]string{
			winKBCmd: "KB9999",
			// Get-Package returns empty => the scanner falls back to the registry.
			winSoftwareGetPackageCmd: "",
			winSoftwareRegistryCmd:   "Git\t2.42.0",
		},
	}
	scanner := NewScanner(mock)
	info := &OSInfo{Family: FamilyWindows}

	kbs, software, err := scanner.GatherWindows(context.Background(), info)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if !reflect.DeepEqual(kbs, []string{"KB9999"}) {
		t.Errorf("kbs = %v", kbs)
	}
	wantSoftware := []vulners.WinAuditItem{{Software: "Git", Version: "2.42.0"}}
	if !reflect.DeepEqual(software, wantSoftware) {
		t.Errorf("software = %+v, want %+v", software, wantSoftware)
	}
}
