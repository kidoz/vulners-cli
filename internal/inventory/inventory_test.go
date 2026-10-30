package inventory

import (
	"os"
	"path/filepath"
	"testing"
)

func TestReadFileAtMost(t *testing.T) {
	path := filepath.Join(t.TempDir(), "input.json")
	if err := os.WriteFile(path, []byte("12345"), 0o600); err != nil {
		t.Fatal(err)
	}
	data, err := readFileAtMost(path, 5)
	if err != nil || string(data) != "12345" {
		t.Fatalf("readFileAtMost() = %q, %v", data, err)
	}
	if _, err := readFileAtMost(path, 4); err == nil {
		t.Fatal("readFileAtMost() should reject oversized input")
	}
}
