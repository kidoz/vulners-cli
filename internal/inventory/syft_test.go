package inventory

import (
	"context"
	"testing"
)

func TestSyftCollector_Collect_EmptyRef(t *testing.T) {
	c := &SyftCollector{}
	_, err := c.Collect(context.Background(), "")
	if err == nil {
		t.Fatal("expected error for empty image ref")
	}
}

func TestSyftCollector_CollectSBOM_EmptyRef(t *testing.T) {
	c := &SyftCollector{}
	_, err := c.CollectSBOM(context.Background(), "")
	if err == nil {
		t.Fatal("expected error for empty image ref")
	}
}

func TestSyftCollector_Collect_InvalidRef(t *testing.T) {
	tests := []string{
		"alpine; rm -rf /",
		"image$(whoami)",
		"image`id`",
		"image | cat",
		"image & echo",
		"image\nnewline",
		"image with spaces",
	}
	for _, ref := range tests {
		c := &SyftCollector{}
		_, err := c.Collect(context.Background(), ref)
		if err == nil {
			t.Errorf("expected error for ref %q, got nil", ref)
		}
	}
}

func TestSyftCollector_CollectSBOM_InvalidRef(t *testing.T) {
	tests := []string{
		"alpine; rm -rf /",
		"image$(whoami)",
		"image | cat",
	}
	for _, ref := range tests {
		c := &SyftCollector{}
		_, err := c.CollectSBOM(context.Background(), ref)
		if err == nil {
			t.Errorf("expected error for ref %q, got nil", ref)
		}
	}
}

func TestParseCycloneDXBytes_ComponentsAndEcosystem(t *testing.T) {
	sbom := `{
		"bomFormat": "CycloneDX",
		"specVersion": "1.4",
		"components": [
			{
				"type": "library",
				"name": "musl",
				"version": "1.2.4-r2",
				"purl": "pkg:apk/alpine/musl@1.2.4-r2?arch=x86_64&distro=alpine-3.18.4"
			},
			{
				"type": "library",
				"name": "express",
				"version": "4.18.2",
				"purl": "pkg:npm/express@4.18.2"
			}
		]
	}`

	result, err := ParseCycloneDXBytes([]byte(sbom))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Components) != 2 {
		t.Fatalf("expected 2 components, got %d", len(result.Components))
	}
	if result.Components[0].Ecosystem != "apk" {
		t.Errorf("expected ecosystem apk, got %s", result.Components[0].Ecosystem)
	}
	if result.Components[1].Ecosystem != "npm" {
		t.Errorf("expected ecosystem npm, got %s", result.Components[1].Ecosystem)
	}
	if result.RawSBOM == nil {
		t.Error("expected RawSBOM to be non-nil")
	}
}

func TestParseCycloneDXBytes_DistroDetection(t *testing.T) {
	sbom := `{
		"bomFormat": "CycloneDX",
		"specVersion": "1.4",
		"metadata": {
			"component": {
				"type": "operating-system",
				"name": "Alpine Linux",
				"version": "3.18.4"
			}
		},
		"components": [
			{
				"type": "library",
				"name": "musl",
				"version": "1.2.4-r2",
				"purl": "pkg:apk/alpine/musl@1.2.4-r2"
			}
		]
	}`

	result, err := ParseCycloneDXBytes([]byte(sbom))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Distro == nil {
		t.Fatal("expected distro to be detected")
	}
	if result.Distro.Name != "alpine linux" {
		t.Errorf("expected distro name 'alpine linux', got %q", result.Distro.Name)
	}
	if result.Distro.Version != "3.18.4" {
		t.Errorf("expected distro version '3.18.4', got %q", result.Distro.Version)
	}
}

func TestParseCycloneDXBytes_NoDistro(t *testing.T) {
	sbom := `{
		"bomFormat": "CycloneDX",
		"specVersion": "1.4",
		"components": [
			{
				"type": "library",
				"name": "cobra",
				"version": "1.7.0",
				"purl": "pkg:golang/github.com/spf13/cobra@1.7.0"
			}
		]
	}`

	result, err := ParseCycloneDXBytes([]byte(sbom))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Distro != nil {
		t.Errorf("expected nil distro for Go-only SBOM, got %+v", result.Distro)
	}
}
