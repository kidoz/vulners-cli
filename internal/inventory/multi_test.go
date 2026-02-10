package inventory

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestMultiCollector_Collect_PipOnly(t *testing.T) {
	dir := t.TempDir()

	pipContent := "requests==2.31.0\nflask>=2.0.0\n"
	if err := os.WriteFile(filepath.Join(dir, "requirements.txt"), []byte(pipContent), 0o600); err != nil {
		t.Fatal(err)
	}

	c := &MultiCollector{}
	components, err := c.Collect(context.Background(), dir)
	if err != nil {
		t.Fatalf("Collect() error: %v", err)
	}

	if len(components) != 2 {
		t.Fatalf("expected 2 pip components, got %d", len(components))
	}

	for _, comp := range components {
		if comp.Type != "pip" {
			t.Errorf("expected type 'pip', got %q", comp.Type)
		}
		if comp.Name == "" {
			t.Error("expected non-empty component name")
		}
		if comp.Version == "" {
			t.Error("expected non-empty component version")
		}
	}
}

func TestMultiCollector_Collect_NPMAndPip(t *testing.T) {
	dir := t.TempDir()

	// Create a package-lock.json
	npmContent := `{
		"name": "test",
		"version": "1.0.0",
		"lockfileVersion": 3,
		"packages": {
			"node_modules/express": {
				"version": "4.18.2"
			}
		}
	}`
	if err := os.WriteFile(filepath.Join(dir, "package-lock.json"), []byte(npmContent), 0o600); err != nil {
		t.Fatal(err)
	}

	// Create a requirements.txt
	pipContent := "requests==2.31.0\nflask>=2.0.0\n"
	if err := os.WriteFile(filepath.Join(dir, "requirements.txt"), []byte(pipContent), 0o600); err != nil {
		t.Fatal(err)
	}

	c := &MultiCollector{}
	components, err := c.Collect(context.Background(), dir)
	if err != nil {
		t.Fatalf("Collect() error: %v", err)
	}

	if len(components) < 3 {
		t.Errorf("expected at least 3 components (1 npm + 2 pip), got %d", len(components))
	}

	// Verify we got components from both ecosystems.
	hasNPM, hasPip := false, false
	for _, c := range components {
		if c.Type == "npm" {
			hasNPM = true
		}
		if c.Type == "pip" {
			hasPip = true
		}
	}
	if !hasNPM {
		t.Error("expected npm components")
	}
	if !hasPip {
		t.Error("expected pip components")
	}
}

func TestMultiCollector_Collect_Deterministic(t *testing.T) {
	dir := t.TempDir()

	npmContent := `{
		"name": "test",
		"version": "1.0.0",
		"lockfileVersion": 3,
		"packages": {
			"node_modules/express": { "version": "4.18.2" }
		}
	}`
	if err := os.WriteFile(filepath.Join(dir, "package-lock.json"), []byte(npmContent), 0o600); err != nil {
		t.Fatal(err)
	}

	pipContent := "requests==2.31.0\n"
	if err := os.WriteFile(filepath.Join(dir, "requirements.txt"), []byte(pipContent), 0o600); err != nil {
		t.Fatal(err)
	}

	c := &MultiCollector{}

	// Run multiple times and verify identical ordering.
	first, err := c.Collect(context.Background(), dir)
	if err != nil {
		t.Fatalf("Collect() error: %v", err)
	}
	for i := 0; i < 10; i++ {
		got, err := c.Collect(context.Background(), dir)
		if err != nil {
			t.Fatalf("Collect() iteration %d error: %v", i, err)
		}
		if len(got) != len(first) {
			t.Fatalf("iteration %d: length mismatch %d vs %d", i, len(got), len(first))
		}
		for j := range first {
			if got[j].Type != first[j].Type || got[j].Name != first[j].Name || got[j].Version != first[j].Version {
				t.Fatalf("iteration %d: component %d differs: %+v vs %+v", i, j, got[j], first[j])
			}
		}
	}
}

func TestMultiCollector_Collect_EmptyDir(t *testing.T) {
	dir := t.TempDir()
	c := &MultiCollector{}
	components, err := c.Collect(context.Background(), dir)
	if err != nil {
		t.Fatalf("Collect() error: %v", err)
	}
	if len(components) != 0 {
		t.Errorf("expected 0 components for empty dir, got %d", len(components))
	}
}
