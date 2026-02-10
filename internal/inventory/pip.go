package inventory

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/kidoz/vulners-cli/internal/model"
)

// PipCollector collects components from requirements.txt.
type PipCollector struct{}

func (c *PipCollector) Collect(_ context.Context, target string) ([]model.Component, error) {
	f, err := os.Open(target)
	if err != nil {
		return nil, fmt.Errorf("reading requirements.txt: %w", err)
	}
	defer func() { _ = f.Close() }()

	var components []model.Component
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "-") {
			continue
		}

		name, version := parsePipRequirement(line)
		if name == "" {
			continue
		}

		purl := fmt.Sprintf("pkg:pypi/%s", name)
		if version != "" {
			purl += "@" + version
		}
		components = append(components, model.Component{
			Type:      "pip",
			Name:      name,
			Version:   version,
			PURL:      purl,
			Locations: []string{target},
		})
	}

	sort.Slice(components, func(i, j int) bool {
		return components[i].Name < components[j].Name
	})

	return components, scanner.Err()
}

func parsePipRequirement(line string) (name, version string) {
	// Remove environment markers (e.g. "; python_version >= '3.6'")
	if idx := strings.Index(line, ";"); idx > 0 {
		line = strings.TrimSpace(line[:idx])
	}
	// Remove extras (e.g. "package[extra]")
	if idx := strings.Index(line, "["); idx > 0 {
		rest := line[idx:]
		endBracket := strings.Index(rest, "]")
		if endBracket > 0 {
			line = line[:idx] + rest[endBracket+1:]
		}
	}

	// Split on version specifiers: ==, >=, <=, ~=, !=, >, <
	for _, sep := range []string{"==", ">=", "<=", "~=", "!=", ">", "<"} {
		if idx := strings.Index(line, sep); idx > 0 {
			name = strings.TrimSpace(line[:idx])
			version = strings.TrimSpace(line[idx+len(sep):])
			// Take only first version for ranges (e.g. ">=1.0,<2.0" → "1.0")
			if commaIdx := strings.Index(version, ","); commaIdx > 0 {
				version = version[:commaIdx]
			}
			return name, version
		}
	}

	return strings.TrimSpace(line), ""
}
