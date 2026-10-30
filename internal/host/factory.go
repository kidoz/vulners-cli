package host

import (
	"context"
	"fmt"
	"log/slog"
	"net/url"
	"os"
	"time"

	"golang.org/x/term"
)

// ExecutorOptions holds configuration for creating an Executor.
type ExecutorOptions struct {
	IdentityFile string
	PasswordEnv  string
	AskPass      bool
	Insecure     bool
	Timeout      time.Duration
}

// NewExecutorFromURI creates a new Executor based on the provided target URI and options.
func NewExecutorFromURI(ctx context.Context, target string, opts ExecutorOptions) (Executor, error) {
	if target == "local" {
		return NewLocalExecutor(), nil
	}

	u, err := url.Parse(target)
	if err != nil {
		return nil, fmt.Errorf("invalid target URI")
	}
	if u.User != nil {
		if _, ok := u.User.Password(); ok {
			return nil, fmt.Errorf("passwords in target URIs are not supported; use --password-env or --ask-pass")
		}
	}

	switch u.Scheme {
	case "ssh":
		return createSSHExecutor(u, opts)
	case "winrm", "winrms":
		return createWinRMExecutor(u, opts)
	default:
		return nil, fmt.Errorf("unsupported target scheme: %s", u.Scheme)
	}
}

func getPassword(u *url.URL, opts ExecutorOptions) (string, error) {
	if opts.PasswordEnv != "" {
		if p := os.Getenv(opts.PasswordEnv); p != "" {
			return p, nil
		}
	}
	if opts.AskPass {
		_, _ = fmt.Fprintf(os.Stderr, "Password for %s: ", u.User.Username())
		//nolint:unconvert,gosec // Type conversion from int to int is needed on some platforms
		passBytes, err := term.ReadPassword(int(os.Stdin.Fd()))
		_, _ = fmt.Fprintln(os.Stderr)
		if err != nil {
			return "", fmt.Errorf("failed to read password: %w", err)
		}
		return string(passBytes), nil
	}
	return "", nil
}

func createSSHExecutor(u *url.URL, opts ExecutorOptions) (*SSHExecutor, error) {
	pass, err := getPassword(u, opts)
	if err != nil {
		return nil, err
	}

	sshOpts := SSHOptions{
		Host:         u.Hostname(),
		Port:         u.Port(),
		User:         u.User.Username(),
		IdentityFile: opts.IdentityFile,
		Password:     pass,
		Insecure:     opts.Insecure,
		Timeout:      opts.Timeout,
	}

	sshExec, errSSH := NewSSHExecutor(sshOpts)
	if errSSH != nil {
		return nil, fmt.Errorf("failed to initialize SSH executor: %w", errSSH)
	}
	return sshExec, nil
}

func createWinRMExecutor(u *url.URL, opts ExecutorOptions) (*WinRMExecutor, error) {
	if u.User.Username() == "" {
		return nil, fmt.Errorf("WinRM requires a username; use winrms://user@host")
	}
	if u.Scheme == "winrm" && u.Port() != "5986" {
		slog.Warn("WinRM connection uses HTTP without TLS; credentials and command output lack transport encryption; use winrms://")
	}
	pass, err := getPassword(u, opts)
	if err != nil {
		return nil, err
	}
	if pass == "" {
		return nil, fmt.Errorf("password is required for winrm (use --password-env or --ask-pass)")
	}

	winrmOpts := WinRMOptions{
		Host:     u.Hostname(),
		Port:     u.Port(),
		User:     u.User.Username(),
		Password: pass,
		HTTPS:    u.Scheme == "winrms" || u.Port() == "5986",
		Insecure: opts.Insecure,
		Timeout:  opts.Timeout,
	}

	winrmExec, errWinRM := NewWinRMExecutor(winrmOpts)
	if errWinRM != nil {
		return nil, fmt.Errorf("failed to initialize WinRM executor: %w", errWinRM)
	}
	return winrmExec, nil
}
