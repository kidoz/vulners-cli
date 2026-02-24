package host

import (
	"context"
	"fmt"
	"reflect"
	"testing"
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
			"(Get-CimInstance Win32_OperatingSystem).Caption": "Microsoft Windows 10 Pro",
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

	expected := &OSInfo{Family: FamilyWindows, OSName: "Microsoft Windows 10 Pro"}
	if !reflect.DeepEqual(info, expected) {
		t.Errorf("expected %+v, got %+v", expected, info)
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
