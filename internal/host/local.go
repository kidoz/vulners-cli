package host

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"runtime"
	"strings"
)

// LocalExecutor executes commands on the local machine.
type LocalExecutor struct{}

// NewLocalExecutor returns a new LocalExecutor.
func NewLocalExecutor() *LocalExecutor {
	return &LocalExecutor{}
}

// Execute runs the given command locally using the appropriate shell.
//
//nolint:gosec // Intentional execution of dynamic commands for local host scanning.
func (e *LocalExecutor) Execute(ctx context.Context, cmd string) (string, error) {
	var c *exec.Cmd
	//nolint:gosec // Intentional execution of dynamic commands for local host scanning.
	if runtime.GOOS == "windows" {
		c = exec.CommandContext(ctx, "powershell", "-NoProfile", "-NonInteractive", "-Command", cmd)
	} else {
		c = exec.CommandContext(ctx, "sh", "-c", cmd)
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	c.Stdout = &stdout
	c.Stderr = &stderr

	if err := c.Run(); err != nil {
		return "", fmt.Errorf("command execution failed: %w\nCommand: %s\nStderr: %s", err, cmd, strings.TrimSpace(stderr.String()))
	}

	return strings.TrimSpace(stdout.String()), nil
}

// Close is a no-op for LocalExecutor.
func (e *LocalExecutor) Close() error {
	return nil
}
