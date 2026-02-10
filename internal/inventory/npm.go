package inventory

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/kidoz/vulners-cli/internal/model"
)

// NPMCollector collects components from package-lock.json.
type NPMCollector struct{}

func (c *NPMCollector) Collect(_ context.Context, target string) ([]model.Component, error) {
	data, err := os.ReadFile(target)
	if err != nil {
		return nil, fmt.Errorf("reading package-lock.json: %w", err)
	}

	var lockfile struct {
		Packages map[string]struct {
			Version string `json:"version"`
		} `json:"packages"`
		// npm v1 lockfile format
		Dependencies map[string]struct {
			Version string `json:"version"`
		} `json:"dependencies"`
	}
	if err := json.Unmarshal(data, &lockfile); err != nil {
		return nil, fmt.Errorf("parsing package-lock.json: %w", err)
	}

	var components []model.Component

	// Prefer v2/v3 "packages" field.
	if len(lockfile.Packages) > 0 {
		for path, pkg := range lockfile.Packages {
			if path == "" || pkg.Version == "" {
				continue // skip root package
			}
			// path is like "node_modules/lodash" or "node_modules/@scope/pkg"
			// Nested deps: "node_modules/foo/node_modules/bar" → "bar"
			name := path
			if i := strings.LastIndex(path, "node_modules/"); i >= 0 {
				name = path[i+len("node_modules/"):]
			}
			components = append(components, model.Component{
				Type:      "npm",
				Name:      name,
				Version:   pkg.Version,
				PURL:      npmPURL(name, pkg.Version),
				Locations: []string{target},
			})
		}
	} else {
		// Fallback to v1 "dependencies" field.
		for name, dep := range lockfile.Dependencies {
			if dep.Version == "" {
				continue
			}
			components = append(components, model.Component{
				Type:      "npm",
				Name:      name,
				Version:   dep.Version,
				PURL:      npmPURL(name, dep.Version),
				Locations: []string{target},
			})
		}
	}

	sort.Slice(components, func(i, j int) bool {
		return components[i].Name < components[j].Name
	})

	return components, nil
}

// npmPURL builds a spec-compliant Package URL for npm packages.
// Scoped packages (e.g. @babel/core) use the scope as namespace: pkg:npm/%40babel/core@7.0.0
func npmPURL(name, version string) string {
	if strings.HasPrefix(name, "@") {
		parts := strings.SplitN(name[1:], "/", 2)
		if len(parts) == 2 {
			return fmt.Sprintf("pkg:npm/%%40%s/%s@%s", parts[0], parts[1], version)
		}
	}
	return fmt.Sprintf("pkg:npm/%s@%s", name, version)
}
