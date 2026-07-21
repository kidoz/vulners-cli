package host

import (
	"context"
	"encoding/csv"
	"fmt"
	"log/slog"
	"strings"

	vulners "github.com/kidoz/go-vulners"
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
	Version string // Linux: VERSION_ID from os-release; Windows: full version (e.g. "10.0.19045")
	OSName  string // For Windows: Caption (raw, e.g. "Microsoft Windows 10 Pro")

	// BuildNumber is the Windows build segment used to disambiguate Windows 10
	// vs Windows 11 (captions report "Windows 10" for both).
	BuildNumber string
}

// Scanner performs host inventory scanning.
type Scanner struct {
	exec   Executor
	logger *slog.Logger
}

// NewScanner creates a new Scanner using the provided Executor. A nil logger
// discards diagnostic output.
func NewScanner(exec Executor, logger *slog.Logger) *Scanner {
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	return &Scanner{exec: exec, logger: logger}
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

	// Fallback to Windows: prefer the CSV query (Caption + Version +
	// BuildNumber), then fall back to the plain Caption query for hosts where
	// ConvertTo-Csv is unavailable or behaves unexpectedly.
	if info, ok := s.detectWindowsCSV(ctx); ok {
		return info, nil
	}
	if out, err := s.exec.Execute(ctx, winOSDetectCaptionCmd); err == nil && strings.TrimSpace(out) != "" {
		return &OSInfo{Family: FamilyWindows, OSName: strings.TrimSpace(out)}, nil
	}

	return nil, fmt.Errorf("unable to detect supported operating system")
}

// detectWindowsCSV runs the CSV OS-detection query and returns the parsed
// OSInfo. The boolean indicates whether detection succeeded.
func (s *Scanner) detectWindowsCSV(ctx context.Context) (*OSInfo, bool) {
	out, err := s.exec.Execute(ctx, winOSDetectCmd)
	if err != nil || strings.TrimSpace(out) == "" {
		return nil, false
	}
	caption, version, build := parseWindowsOSCSV(out)
	if caption == "" {
		return nil, false
	}
	return &OSInfo{Family: FamilyWindows, OSName: caption, Version: version, BuildNumber: build}, true
}

// parseWindowsOSCSV extracts Caption, Version and BuildNumber from the output
// of `Get-CimInstance Win32_OperatingSystem | Select-Object
// Caption,Version,BuildNumber | ConvertTo-Csv -NoTypeInformation`.
// ConvertTo-Csv quotes every field.
func parseWindowsOSCSV(output string) (caption, version, build string) {
	reader := csv.NewReader(strings.NewReader(output))
	reader.FieldsPerRecord = -1 // tolerate trailing whitespace rows
	records, err := reader.ReadAll()
	if err != nil || len(records) < 2 {
		return "", "", ""
	}

	headerIdx := findCSVHeader(records)
	if headerIdx == -1 {
		// No header row: treat the first non-empty record as the data row,
		// with columns in query order (Caption, Version, BuildNumber).
		for _, row := range records {
			if len(row) >= 2 && strings.TrimSpace(row[0]) != "" {
				caption = strings.TrimSpace(row[0])
				version = strings.TrimSpace(row[1])
				if len(row) >= 3 {
					build = strings.TrimSpace(row[2])
				}
				return caption, version, build
			}
		}
		return "", "", ""
	}

	header := records[headerIdx]
	if headerIdx+1 >= len(records) {
		return "", "", ""
	}
	data := records[headerIdx+1]
	caption = csvField(data, csvColumnIndex(header, "caption"))
	version = csvField(data, csvColumnIndex(header, "version"))
	build = csvField(data, csvColumnIndex(header, "buildnumber"))
	return caption, version, build
}

// csvField returns the trimmed cell at idx, or "" when idx is out of range.
func csvField(row []string, idx int) string {
	if idx < 0 || idx >= len(row) {
		return ""
	}
	return strings.TrimSpace(row[idx])
}

// findCSVHeader returns the index of the row whose first cell is "Caption"
// (case-insensitive), or -1 when no header is present.
func findCSVHeader(records [][]string) int {
	for i, row := range records {
		if len(row) >= 2 && strings.EqualFold(strings.TrimSpace(row[0]), "Caption") {
			return i
		}
	}
	return -1
}

// csvColumnIndex returns the position of the named column (case-insensitive),
// or -1 when absent.
func csvColumnIndex(header []string, name string) int {
	for i, col := range header {
		if strings.EqualFold(strings.TrimSpace(col), name) {
			return i
		}
	}
	return -1
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

// GatherPackages retrieves the list of installed Linux packages for the
// detected OS family. Use GatherWindows for Windows hosts.
func (s *Scanner) GatherPackages(ctx context.Context, info *OSInfo) ([]string, error) {
	var cmd string
	switch info.Family {
	case FamilyDeb:
		cmd = "dpkg-query -W -f='${Package} ${Version} ${Architecture}\\n'"
	case FamilyRPM:
		cmd = "rpm -qa --qf '%{NAME} %{VERSION}-%{RELEASE} %{ARCH}\\n'"
	case FamilyAlpine:
		cmd = "apk info -v"
	default:
		return nil, fmt.Errorf("unsupported OS family: %s (use GatherWindows for Windows)", info.Family)
	}

	out, err := s.exec.Execute(ctx, cmd)
	if err != nil {
		return nil, fmt.Errorf("failed to gather packages: %w", err)
	}

	return parseLines(out), nil
}

// GatherWindows retrieves installed KBs and software inventory from a Windows
// host. Software is collected via Get-Package first, falling back to the
// Uninstall registry keys when Get-Package returns nothing or fails.
func (s *Scanner) GatherWindows(ctx context.Context, _ *OSInfo) ([]string, []vulners.WinAuditItem, error) {
	kbOut, err := s.exec.Execute(ctx, winKBCmd)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to gather Windows KBs: %w", err)
	}
	kbs := parseLines(kbOut)

	software, sErr := s.gatherWindowsSoftware(ctx)
	if sErr != nil {
		// Only hard-fail when we collected nothing at all; a KB-only result is
		// still useful and the API accepts an empty software list.
		if len(kbs) == 0 {
			return nil, nil, fmt.Errorf("failed to gather Windows software: %w", sErr)
		}
		s.logger.Warn("failed to gather Windows software, continuing with KBs only", "error", sErr)
	}

	return kbs, software, nil
}

// gatherWindowsSoftware tries Get-Package and falls back to the registry scan
// when the primary source returns nothing or fails.
func (s *Scanner) gatherWindowsSoftware(ctx context.Context) ([]vulners.WinAuditItem, error) {
	if out, err := s.exec.Execute(ctx, winSoftwareGetPackageCmd); err == nil {
		if items := ParseWindowsSoftware(parseLines(out)); len(items) > 0 {
			return items, nil
		}
	}

	out, err := s.exec.Execute(ctx, winSoftwareRegistryCmd)
	if err != nil {
		return nil, err
	}
	return ParseWindowsSoftware(parseLines(out)), nil
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
