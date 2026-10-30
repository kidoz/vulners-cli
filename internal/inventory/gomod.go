package inventory

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/kidoz/vulners-cli/internal/model"
	"github.com/kidoz/vulners-cli/internal/scanbudget"
)

// GoModCollector collects components from go.mod and go.sum files.
type GoModCollector struct{}

func (c *GoModCollector) Collect(_ context.Context, target string) ([]model.Component, error) {
	goModPath := target
	if filepath.Base(target) != "go.mod" {
		goModPath = filepath.Join(target, "go.mod")
	}
	if _, err := os.Stat(goModPath); err != nil {
		return nil, fmt.Errorf("go.mod not found in %s: %w", target, err)
	}

	return parseGoMod(goModPath)
}

func parseGoMod(path string) ([]model.Component, error) {
	data, err := readFileLimited(path)
	if err != nil {
		return nil, fmt.Errorf("reading go.mod: %w", err)
	}

	var components []model.Component
	scanner := bufio.NewScanner(bytes.NewReader(data))
	inRequire := false

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		if strings.HasPrefix(line, "require (") || strings.HasPrefix(line, "require(") {
			inRequire = true
			continue
		}
		if inRequire && line == ")" {
			inRequire = false
			continue
		}

		if inRequire {
			comp := parseRequireLine(line, path)
			if comp != nil {
				if err := scanbudget.CheckComponents(len(components) + 1); err != nil {
					return nil, err
				}
				components = append(components, *comp)
			}
		} else if strings.HasPrefix(line, "require ") {
			rest := strings.TrimPrefix(line, "require ")
			comp := parseRequireLine(rest, path)
			if comp != nil {
				if err := scanbudget.CheckComponents(len(components) + 1); err != nil {
					return nil, err
				}
				components = append(components, *comp)
			}
		}
	}

	sort.Slice(components, func(i, j int) bool {
		return components[i].Name < components[j].Name
	})

	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return components, nil
}

func parseRequireLine(line, goModPath string) *model.Component {
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, "//") {
		return nil
	}

	// Remove inline comments.
	if idx := strings.Index(line, "//"); idx > 0 {
		line = strings.TrimSpace(line[:idx])
	}

	parts := strings.Fields(line)
	if len(parts) < 2 {
		return nil
	}

	name := parts[0]
	version := parts[1]

	return &model.Component{
		Type:      "go-module",
		Name:      name,
		Version:   version,
		PURL:      goPURL(name, version),
		Locations: []string{goModPath},
	}
}

func goPURL(module, version string) string {
	return fmt.Sprintf("pkg:golang/%s@%s", module, version)
}
