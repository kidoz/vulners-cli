package host

import (
	"context"
	"io"
	"net/url"
	"os"
	"strings"
	"testing"
)

func TestNewExecutorFromURI_DoesNotExposePassword(t *testing.T) {
	targets := []string{
		"ssh://user:fake-secret@example%",
		"ssh://user:fake-secret@example.com",
	}
	for _, target := range targets {
		_, err := NewExecutorFromURI(context.Background(), target, ExecutorOptions{})
		if err == nil {
			t.Fatalf("NewExecutorFromURI(%q) should reject the target", target)
		}
		if strings.Contains(err.Error(), "fake-secret") {
			t.Fatalf("error contains password: %v", err)
		}
	}
}

func TestGetPassword_PromptUsesStderr(t *testing.T) {
	oldStdout, oldStderr := os.Stdout, os.Stderr
	stdoutR, stdoutW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	stderrR, stderrW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout, os.Stderr = stdoutW, stderrW
	defer func() { os.Stdout, os.Stderr = oldStdout, oldStderr }()

	u, _ := url.Parse("ssh://user@example.com")
	_, _ = getPassword(u, ExecutorOptions{AskPass: true})
	_ = stdoutW.Close()
	_ = stderrW.Close()
	stdout, _ := io.ReadAll(stdoutR)
	stderr, _ := io.ReadAll(stderrR)
	if len(stdout) != 0 {
		t.Fatalf("password prompt wrote to stdout: %q", stdout)
	}
	if !strings.Contains(string(stderr), "Password for user:") {
		t.Fatalf("password prompt missing from stderr: %q", stderr)
	}
}
