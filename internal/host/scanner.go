package host

import (
	"context"
	"fmt"
	"strings"
)

// OSFamily represents the package management family of an OS.
type OSFamily string

const (
	FamilyDeb     OSFamily = "debian"
	FamilyRPM     OSFamily = "rpm"
	FamilyAlpine  OSFamily = "alpine"
	FamilyWindows OSFamily = "windows"
	FamilyUnknown OSFamily = "unknown"
)

// OSInfo holds the fingerprinted operating system data.
type OSInfo struct {
	Family  OSFamily
	Distro  string // For Linux: ID from os-release
	Version string // For Linux: VERSION_ID from os-release
	OSName  string // For Windows: Caption
}

// Scanner performs host inventory scanning.
type Scanner struct {
	exec Executor
}

// NewScanner creates a new Scanner using the provided Executor.
func NewScanner(exec Executor) *Scanner {
	return &Scanner{exec: exec}
}

// DetectOS attempts to determine the target's operating system using the executor.
func (s *Scanner) DetectOS(ctx context.Context) (*OSInfo, error) {
	// Try a common Linux command first
	out, err := s.exec.Execute(ctx, "uname -s")
	if err == nil {
		lowerOut := strings.ToLower(out)
		if strings.Contains(lowerOut, "linux") {
			return s.detectLinux(ctx)
		}
		if strings.Contains(lowerOut, "darwin") {
			return nil, fmt.Errorf("macOS is not supported for host scanning")
		}
	}

	// Fallback to trying Windows WMI / PowerShell
	out, err = s.exec.Execute(ctx, "(Get-CimInstance Win32_OperatingSystem).Caption")
	if err == nil && out != "" {
		return &OSInfo{Family: FamilyWindows, OSName: strings.TrimSpace(out)}, nil
	}

	return nil, fmt.Errorf("unable to detect supported operating system")
}

// detectLinux fingerprints a Linux distribution by parsing /etc/os-release.
//
//nolint:gocyclo // Parsing multiple OS families inherently requires branching.
func (s *Scanner) detectLinux(ctx context.Context) (*OSInfo, error) {
	out, err := s.exec.Execute(ctx, "cat /etc/os-release")
	if err != nil {
		return nil, fmt.Errorf("failed to read /etc/os-release: %w", err)
	}

	info := &OSInfo{}
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "ID=") {
			info.Distro = strings.Trim(strings.TrimPrefix(line, "ID="), `"'`)
		} else if strings.HasPrefix(line, "VERSION_ID=") {
			info.Version = strings.Trim(strings.TrimPrefix(line, "VERSION_ID="), `"'`)
		} else if strings.HasPrefix(line, "ID_LIKE=") {
			like := strings.ToLower(strings.Trim(strings.TrimPrefix(line, "ID_LIKE="), `"'`))
			if strings.Contains(like, "debian") || strings.Contains(like, "ubuntu") {
				info.Family = FamilyDeb
			} else if strings.Contains(like, "rhel") || strings.Contains(like, "centos") || strings.Contains(like, "fedora") || strings.Contains(like, "rocky") || strings.Contains(like, "alma") || strings.Contains(like, "suse") {
				info.Family = FamilyRPM
			} else if strings.Contains(like, "alpine") {
				info.Family = FamilyAlpine
			}
		}
	}

	// Fallback if ID_LIKE didn't provide a family
	if info.Family == "" {
		switch strings.ToLower(info.Distro) {
		case "ubuntu", "debian", "kali", "mint", "pop", "raspbian", "linuxmint", "elementary", "zorin", "deepin", "parrot", "devuan", "mx":
			info.Family = FamilyDeb
		case "centos", "redhat", "rhel", "fedora", "rocky", "alma", "amazon", "amazonlinux", "amzn", "oracle", "oraclelinux", "suse", "opensuse", "opensuse-leap", "opensuse-tumbleweed", "sles":
			info.Family = FamilyRPM
		case "alpine":
			info.Family = FamilyAlpine
		default:
			info.Family = FamilyUnknown
		}
	}

	return info, nil
}

// GatherPackages retrieves the list of installed packages or updates based on the OS family.
func (s *Scanner) GatherPackages(ctx context.Context, info *OSInfo) ([]string, error) {
	var cmd string
	switch info.Family {
	case FamilyDeb:
		cmd = "dpkg-query -W -f='${Package} ${Version} ${Architecture}\\n'"
	case FamilyRPM:
		cmd = "rpm -qa --qf '%{NAME} %{VERSION}-%{RELEASE} %{ARCH}\\n'"
	case FamilyAlpine:
		cmd = "apk info -v"
	case FamilyWindows:
		cmd = "Get-HotFix | Select-Object -ExpandProperty HotFixID"
	default:
		return nil, fmt.Errorf("unsupported OS family: %s", info.Family)
	}

	out, err := s.exec.Execute(ctx, cmd)
	if err != nil {
		return nil, fmt.Errorf("failed to gather packages: %w", err)
	}

	return parseLines(out), nil
}

func parseLines(output string) []string {
	var lines []string
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			lines = append(lines, line)
		}
	}
	return lines
}
