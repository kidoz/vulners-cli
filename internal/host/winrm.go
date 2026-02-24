package host

import (
	"bytes"
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/masterzen/winrm"
)

// WinRMExecutor executes commands on a remote Windows host via WinRM.
type WinRMExecutor struct {
	client *winrm.Client
}

// WinRMOptions holds the configuration for a WinRM connection.
type WinRMOptions struct {
	Host     string
	Port     string
	User     string
	Password string //nolint:gosec // false positive for struct field name
	HTTPS    bool
	Insecure bool
	Timeout  time.Duration
}

// NewWinRMExecutor connects to a WinRM endpoint and returns a WinRMExecutor.
func NewWinRMExecutor(opts WinRMOptions) (*WinRMExecutor, error) {
	if opts.Port == "" {
		if opts.HTTPS {
			opts.Port = "5986" // Default WinRM HTTPS port
		} else {
			opts.Port = "5985" // Default WinRM HTTP port
		}
	}
	port, err := strconv.Atoi(opts.Port)
	if err != nil {
		return nil, fmt.Errorf("invalid port %s: %w", opts.Port, err)
	}

	if opts.Timeout == 0 {
		opts.Timeout = 60 * time.Second
	}

	endpoint := winrm.NewEndpoint(opts.Host, port, opts.HTTPS, opts.Insecure, nil, nil, nil, opts.Timeout)

	client, err := winrm.NewClient(endpoint, opts.User, opts.Password)
	if err != nil {
		return nil, fmt.Errorf("failed to create WinRM client: %w", err)
	}

	return &WinRMExecutor{client: client}, nil
}

// Execute runs the command on the remote host over WinRM.
func (e *WinRMExecutor) Execute(ctx context.Context, cmd string) (string, error) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	// WinRM uses PowerShell. Execute via PowerShell to match local behavior.
	psCmd := winrm.Powershell(cmd)

	exitCode, err := e.client.RunWithContextWithInput(ctx, psCmd, &stdout, &stderr, nil)
	if err != nil {
		return "", fmt.Errorf("command execution failed: %w\nCommand: %s\nStderr: %s", err, cmd, strings.TrimSpace(stderr.String()))
	}
	if exitCode != 0 {
		return "", fmt.Errorf("command exited with code %d\nCommand: %s\nStderr: %s", exitCode, cmd, strings.TrimSpace(stderr.String()))
	}

	return strings.TrimSpace(stdout.String()), nil
}

// Close is a no-op for WinRMExecutor as the client does not maintain an active TCP connection pool.
func (e *WinRMExecutor) Close() error {
	return nil
}
