package host

import (
	"bytes"
	"context"
	"io"
	"log/slog"
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

func TestNewExecutorFromURI_MissingUser(t *testing.T) {
	t.Setenv("SSH_AUTH_SOCK", "")
	_, err := NewExecutorFromURI(context.Background(), "ssh://example.com", ExecutorOptions{})
	if err == nil || !strings.Contains(err.Error(), "authentication methods") {
		t.Fatalf("SSH should reach normal auth validation: %v", err)
	}
	for _, target := range []string{"winrm://example.com", "winrms://example.com"} {
		_, err := NewExecutorFromURI(context.Background(), target, ExecutorOptions{})
		if err == nil || !strings.Contains(err.Error(), "requires a username") {
			t.Fatalf("WinRM should require a username: %v", err)
		}
	}
}

func TestWinRM_HTTPWarns(t *testing.T) {
	t.Setenv("TEST_WINRM_PASSWORD", "fake-password")
	oldLogger := slog.Default()
	defer slog.SetDefault(oldLogger)
	for _, target := range []string{"winrm://user@example.com", "winrms://user@example.com", "winrm://user@example.com:5986"} {
		var logs bytes.Buffer
		slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))
		u, err := url.Parse(target)
		if err != nil {
			t.Fatal(err)
		}
		executor, err := createWinRMExecutor(u, ExecutorOptions{PasswordEnv: "TEST_WINRM_PASSWORD"}) //nolint:gosec // Environment variable name, not a credential.
		if err != nil {
			t.Fatal(err)
		}
		_ = executor.Close()
		wantWarning := target == "winrm://user@example.com"
		if strings.Contains(logs.String(), "without TLS") != wantWarning {
			t.Fatalf("unexpected transport warning for %s: %s", target, logs.String())
		}
		if strings.Contains(logs.String(), "fake-password") {
			t.Fatal("warning leaked password")
		}
	}
}
