package inventory

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/kidoz/vulners-cli/internal/model"
	"github.com/kidoz/vulners-cli/internal/scanbudget"
)

type npmDependency struct {
	Version      string                   `json:"version"`
	Dependencies map[string]npmDependency `json:"dependencies"`
}

type npmLockfile struct {
	Packages map[string]struct {
		Version string `json:"version"`
	} `json:"packages"`
	Dependencies map[string]npmDependency `json:"dependencies"`
}

// NPMCollector collects components from package-lock.json.
type NPMCollector struct{}

func (c *NPMCollector) Collect(ctx context.Context, target string) ([]model.Component, error) {
	data, err := readFileLimited(target)
	if err != nil {
		return nil, fmt.Errorf("reading package-lock.json: %w", err)
	}
	var lockfile npmLockfile
	if err := json.Unmarshal(data, &lockfile); err != nil {
		return nil, fmt.Errorf("parsing package-lock.json: %w", err)
	}
	var components []model.Component
	seen := make(map[string]bool)
	if len(lockfile.Packages) > 0 {
		for path, pkg := range lockfile.Packages {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			if path == "" {
				continue
			}
			name := path
			if i := strings.LastIndex(path, "node_modules/"); i >= 0 {
				name = path[i+len("node_modules/"):]
			}
			if err := appendNPMComponent(&components, seen, name, pkg.Version, target); err != nil {
				return nil, err
			}
		}
	} else if err := collectNPMDependencies(ctx, lockfile.Dependencies, target, seen, &components); err != nil {
		return nil, err
	}
	sort.Slice(components, func(i, j int) bool {
		if components[i].Name != components[j].Name {
			return components[i].Name < components[j].Name
		}
		return components[i].Version < components[j].Version
	})
	return components, nil
}

func collectNPMDependencies(ctx context.Context, deps map[string]npmDependency, target string, seen map[string]bool, components *[]model.Component) error {
	for name, dep := range deps {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := appendNPMComponent(components, seen, name, dep.Version, target); err != nil {
			return err
		}
		if err := collectNPMDependencies(ctx, dep.Dependencies, target, seen, components); err != nil {
			return err
		}
	}
	return nil
}

func appendNPMComponent(components *[]model.Component, seen map[string]bool, name, version, target string) error {
	if version == "" || seen[name+"\x00"+version] {
		return nil
	}
	if err := scanbudget.CheckComponents(len(*components) + 1); err != nil {
		return err
	}
	seen[name+"\x00"+version] = true
	*components = append(*components, model.Component{Type: "npm", Name: name, Version: version, PURL: npmPURL(name, version), Locations: []string{target}})
	return nil
}

// npmPURL builds a spec-compliant Package URL for npm packages.
func npmPURL(name, version string) string {
	if strings.HasPrefix(name, "@") {
		parts := strings.SplitN(name[1:], "/", 2)
		if len(parts) == 2 {
			return fmt.Sprintf("pkg:npm/%%40%s/%s@%s", parts[0], parts[1], version)
		}
	}
	return fmt.Sprintf("pkg:npm/%s@%s", name, version)
}
