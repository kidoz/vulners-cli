// Package cmd provides the command-line interface for the vulners-cli.
package cmd

import (
	"context"
	"fmt"
	"runtime"
	"strings"
)

// distroType represents the package management family of a distribution.
type distroType int

const (
	distroUnknown distroType = iota
	distroDebian             // dpkg-based: requires "name version arch"
	distroRPM                // rpm-based: requires "name version"
)

var distroMap = map[string]distroType{
	"ubuntu":      distroDebian,
	"debian":      distroDebian,
	"kali":        distroDebian,
	"mint":        distroDebian,
	"linuxmint":   distroDebian,
	"pop":         distroDebian,
	"elementary":  distroDebian,
	"zorin":       distroDebian,
	"deepin":      distroDebian,
	"parrot":      distroDebian,
	"raspbian":    distroDebian,
	"devuan":      distroDebian,
	"mx":          distroDebian,
	"centos":      distroRPM,
	"redhat":      distroRPM,
	"rhel":        distroRPM,
	"fedora":      distroRPM,
	"amazonlinux": distroRPM,
	"oraclelinux": distroRPM,
	"rocky":       distroRPM,
	"alma":        distroRPM,
	"suse":        distroRPM,
	"opensuse":    distroRPM,
}

// LinuxAuditCmd audits Linux distribution packages.
type LinuxAuditCmd struct {
	Distro  string   `help:"Linux distribution name (e.g. ubuntu, debian, centos)" required:""`
	Version string   `help:"Distribution version (e.g. 22.04)" required:""`
	Pkg     []string `help:"Package as name=version or 'name version arch'. Deb-based distros require arch (auto-detected if omitted)." required:""`
	Arch    string   `help:"Default architecture to append when not specified in --pkg (e.g. amd64)" default:""`
}

func getDistroType(distro string) distroType {
	if t, ok := distroMap[strings.ToLower(distro)]; ok {
		return t
	}
	return distroUnknown
}

// normalizePackages converts packages from shorthand formats to the format
// expected by the Vulners API.
func normalizePackages(pkgs []string, distro, defaultArch string) []string {
	dtype := getDistroType(distro)
	out := make([]string, 0, len(pkgs))

	for _, p := range pkgs {
		// Convert "name=version" → "name version"
		p = strings.ReplaceAll(p, "=", " ")
		fields := strings.Fields(p)
		if len(fields) == 0 {
			continue
		}

		normalized := strings.Join(fields, " ")

		// For deb-based distros, ensure architecture is present (requires 3 fields)
		if dtype == distroDebian && len(fields) == 2 {
			arch := defaultArch
			if arch == "" {
				arch = debArch()
			}
			normalized = normalized + " " + arch
		}
		out = append(out, normalized)
	}
	return out
}

// debArch returns a sensible Debian architecture string.
func debArch() string {
	// If we are on Linux, we can trust the local architecture more.
	// Otherwise, amd64 is the most common target for remote audits.
	if runtime.GOOS != "linux" {
		return "amd64"
	}

	switch runtime.GOARCH {
	case "amd64":
		return "amd64"
	case "arm64":
		return "arm64"
	case "386":
		return "i386"
	case "arm":
		return "armhf"
	default:
		return "amd64"
	}
}

func (c *LinuxAuditCmd) Run(ctx context.Context, globals *CLI, deps *Deps) error {
	if err := validateNonScanFormat(globals.Output); err != nil {
		return err
	}
	if globals.Offline {
		return fmt.Errorf("linux audit does not support offline mode")
	}
	if deps.Intel == nil {
		return fmt.Errorf("VULNERS_API_KEY is required for audit")
	}

	packages := normalizePackages(c.Pkg, c.Distro, c.Arch)
	if len(packages) == 0 {
		return fmt.Errorf("no packages provided for audit")
	}

	result, err := deps.Intel.LinuxAudit(ctx, c.Distro, c.Version, packages)
	if err != nil {
		return fmt.Errorf("linux audit failed: %w", err)
	}

	w, closer, werr := outputWriter(globals)
	if werr != nil {
		return werr
	}
	defer func() { _ = closer() }()

	return writeIntelOutput(w, globals, "audit linux", result, nil)
}
