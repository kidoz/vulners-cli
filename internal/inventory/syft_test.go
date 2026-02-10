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

func TestSyftCollector_Collect_ValidRefs(t *testing.T) {
	// These should pass validation but fail on missing syft binary.
	// We just check that they don't fail on validation.
	refs := []string{
		"alpine:3.18",
		"docker.io/library/ubuntu:22.04",
		"ghcr.io/owner/image:latest",
		"registry.example.com/foo/bar:v1.2.3",
		"image@sha256:abcdef1234567890",
		"./local-image.tar",
	}
	for _, ref := range refs {
		if !validImageRef.MatchString(ref) {
			t.Errorf("validImageRef should match %q", ref)
		}
	}
}
