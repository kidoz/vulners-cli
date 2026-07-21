package host

import (
	"regexp"
	"strconv"
	"strings"

	vulners "github.com/kidoz/go-vulners"
)

// windowsBuild11Threshold is the first Windows 11 build number.
// Captions for both Windows 10 and Windows 11 report as "Windows 10",
// so the build number is the authoritative disambiguator.
const windowsBuild11Threshold = 22000

// serverYearRe captures the year and optional R2 revision of a
// "Windows Server <year> [R2]" caption. R2 releases are distinct OSes with
// their own patch streams, so the suffix must be preserved.
var serverYearRe = regexp.MustCompile(`(?i)\bserver\s+(20\d{2})(?:\s+(r2))?\b`)

// win10Re detects "Windows 10" captions. Note that Win32_OperatingSystem
// reports "Windows 10" for both Windows 10 and Windows 11; the build number
// is the authoritative disambiguator in that case.
var win10Re = regexp.MustCompile(`(?i)\bwindows\s+10\b`)

// win11ExplicitRe detects captions that already say "Windows 11" (some
// Windows 11 builds and Server 2022 report an explicit major). Used as a
// fast path before the build-number heuristic.
var win11ExplicitRe = regexp.MustCompile(`(?i)\bwindows\s+11\b`)

// legacyClientRe matches legacy client Windows captions that carry their own
// version literal (7, 8, 8.1, Vista, XP).
var legacyClientRe = regexp.MustCompile(`(?i)\bwindows\s+(vista|xp|7|8\.1|8)\b`)

// PowerShell command templates used by the Windows scanner path.
const (
	// winOSDetectCmd returns Caption, Version and BuildNumber as CSV for
	// robust parsing. Version (e.g. "10.0.19045") is forwarded to the audit
	// API as os_version.
	winOSDetectCmd = `Get-CimInstance Win32_OperatingSystem | Select-Object Caption,Version,BuildNumber | ConvertTo-Csv -NoTypeInformation`

	// winOSDetectCaptionCmd is the legacy fallback that queries only the Caption.
	winOSDetectCaptionCmd = `(Get-CimInstance Win32_OperatingSystem).Caption`

	// winKBCmd lists installed KB identifiers via Get-HotFix.
	winKBCmd = `Get-HotFix | Select-Object -ExpandProperty HotFixID`

	// winSoftwareGetPackageCmd enumerates installed software via Get-Package.
	// A tab separates name and version so multi-word product names parse cleanly.
	winSoftwareGetPackageCmd = `Get-Package -ErrorAction SilentlyContinue | Where-Object { $_.Name } | ForEach-Object { "$($_.Name)` + "\t" + `$($_.Version)" }`

	// winSoftwareRegistryCmd is the fallback that reads the Uninstall registry
	// keys, including per-user installs (covers Server Core and hosts without
	// PackageManagement).
	winSoftwareRegistryCmd = `$paths='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*','HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*','HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*'; Get-ItemProperty $paths -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName } | ForEach-Object { "$($_.DisplayName)` + "\t" + `$($_.DisplayVersion)" }`
)

// NormalizeWindowsOS converts the raw Win32_OperatingSystem Caption (and the
// numeric BuildNumber) into the OS identifier expected by the Vulners audit
// API (e.g. "Windows 10", "Windows 11", "Windows Server 2022").
//
// Returns "Windows" when the caption cannot be confidently mapped so that the
// caller surfaces the API's rejection rather than silently miscategorizing.
func NormalizeWindowsOS(caption, buildNumber string) string {
	caption = strings.TrimSpace(caption)
	if caption == "" {
		return "Windows"
	}

	// Strip the leading "Microsoft " prefix when present.
	caption = strings.TrimPrefix(caption, "Microsoft ")
	caption = strings.TrimPrefix(caption, "microsoft ")

	// Windows Server: keep the year and R2 revision, drop edition suffixes.
	if m := serverYearRe.FindStringSubmatch(caption); m != nil {
		name := "Windows Server " + m[1]
		if m[2] != "" {
			name += " R2"
		}
		return name
	}

	// Windows 10/11 family. Real Win32_OperatingSystem captions report
	// "Windows 10" for both Win10 and Win11; the build number disambiguates.
	// Some newer builds report "Windows 11" explicitly, handled first.
	if win11ExplicitRe.MatchString(caption) {
		return "Windows 11"
	}
	if win10Re.MatchString(caption) {
		if parseWindowsBuild(buildNumber) >= windowsBuild11Threshold {
			return "Windows 11"
		}
		return "Windows 10"
	}

	// Legacy client SKUs carry their version literal in the caption.
	if m := legacyClientRe.FindString(caption); m != "" {
		return normalizeCaptionCase(m)
	}

	// Unknown caption: fall back rather than guess.
	return "Windows"
}

// parseWindowsBuild extracts the leading integer from a build string such as
// "10.0.22631" or "22631". Returns 0 when no number can be parsed.
func parseWindowsBuild(build string) int {
	build = strings.TrimSpace(build)
	if build == "" {
		return 0
	}
	// Win32_OperatingSystem.Version uses a Major.Minor.Build form; the build
	// is the last dotted segment.
	if i := strings.LastIndex(build, "."); i >= 0 {
		build = build[i+1:]
	}
	n, err := strconv.Atoi(build)
	if err != nil {
		return 0
	}
	return n
}

// normalizeCaptionCase title-cases a matched "windows <ver>" literal so it
// reads naturally in the API payload (e.g. "Windows 8.1", "Windows XP").
func normalizeCaptionCase(s string) string {
	parts := strings.Fields(s)
	for i, p := range parts {
		if i == 0 {
			parts[i] = "Windows"
			continue
		}
		switch strings.ToLower(p) {
		case "vista":
			parts[i] = "Vista"
		case "xp":
			parts[i] = "XP"
		}
	}
	return strings.Join(parts, " ")
}

// ParseWindowsSoftware converts "name\tversion" lines (tab-separated by the
// PowerShell collector) into WinAuditItem values. Lines without a tab are
// treated as name-only with an empty version.
func ParseWindowsSoftware(lines []string) []vulners.WinAuditItem {
	items := make([]vulners.WinAuditItem, 0, len(lines))
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var item vulners.WinAuditItem
		if name, version, ok := strings.Cut(line, "\t"); ok {
			item.Software = strings.TrimSpace(name)
			item.Version = strings.TrimSpace(version)
		} else {
			item.Software = line
		}
		if item.Software != "" {
			items = append(items, item)
		}
	}
	return items
}
