package host

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/kidoz/vulners-cli/internal/boundedio"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/crypto/ssh/knownhosts"
)

// SSHExecutor executes commands on a remote host via SSH.
type SSHExecutor struct {
	client    *ssh.Client
	agentConn net.Conn
}

// SSHOptions holds the configuration for an SSH connection.
type SSHOptions struct {
	Host         string
	Port         string
	User         string
	IdentityFile string
	Password     string //nolint:gosec // false positive for struct field name
	Insecure     bool
	Timeout      time.Duration
}

// NewSSHExecutor connects to an SSH server and returns an SSHExecutor.
//
//nolint:gocyclo // setup naturally requires branching
func NewSSHExecutor(opts SSHOptions) (*SSHExecutor, error) {
	if opts.Port == "" {
		opts.Port = "22"
	}
	if opts.User == "" {
		opts.User = os.Getenv("USER")
	}

	var authMethods []ssh.AuthMethod
	var agentConn net.Conn
	keepAgent := false
	defer func() {
		if !keepAgent && agentConn != nil {
			_ = agentConn.Close()
		}
	}()

	// 1. Try password if provided
	if opts.Password != "" {
		authMethods = append(authMethods, ssh.Password(opts.Password))
	}

	// 2. Try identity file if provided
	if opts.IdentityFile != "" {
		key, err := os.ReadFile(opts.IdentityFile)
		if err != nil {
			return nil, fmt.Errorf("failed to read identity file %s: %w", opts.IdentityFile, err)
		}
		signer, err := ssh.ParsePrivateKey(key)
		if err != nil {
			return nil, fmt.Errorf("failed to parse identity file: %w", err)
		}
		authMethods = append(authMethods, ssh.PublicKeys(signer))
	}

	// 3. Try ssh-agent as a fallback
	if socket := os.Getenv("SSH_AUTH_SOCK"); socket != "" {
		if signers, conn := loadAgentSigners(socket); len(signers) > 0 {
			agentConn = conn
			authMethods = append(authMethods, ssh.PublicKeys(signers...))
		}
	}

	if len(authMethods) == 0 {
		return nil, fmt.Errorf("no valid SSH authentication methods available (provide password, identity file, or start ssh-agent)")
	}

	var hostKeyCallback ssh.HostKeyCallback
	if opts.Insecure {
		hostKeyCallback = ssh.InsecureIgnoreHostKey() //nolint:gosec
	} else {
		home, err := os.UserHomeDir()
		if err != nil {
			return nil, fmt.Errorf("failed to determine user home dir for known_hosts: %w", err)
		}
		khPath := filepath.Join(home, ".ssh", "known_hosts")
		cb, err := knownhosts.New(khPath)
		if err != nil {
			return nil, fmt.Errorf("failed to load known_hosts (%s): %w", khPath, err)
		}
		hostKeyCallback = cb
	}

	if opts.Timeout == 0 {
		opts.Timeout = 10 * time.Second
	}

	config := &ssh.ClientConfig{
		User:            opts.User,
		Auth:            authMethods,
		HostKeyCallback: hostKeyCallback,
		Timeout:         opts.Timeout,
	}

	addr := net.JoinHostPort(opts.Host, opts.Port)
	client, err := ssh.Dial("tcp", addr, config)
	if err != nil {
		return nil, fmt.Errorf("failed to dial SSH to %s: %w", addr, err)
	}

	keepAgent = true
	return &SSHExecutor{client: client, agentConn: agentConn}, nil
}

func loadAgentSigners(socket string) ([]ssh.Signer, net.Conn) {
	//nolint:gosec // This is connecting to the local SSH agent socket.
	conn, err := net.Dial("unix", socket)
	if err != nil {
		return nil, nil
	}
	signers, err := agent.NewClient(conn).Signers()
	if err != nil || len(signers) == 0 {
		_ = conn.Close()
		return nil, nil
	}
	return signers, conn
}

// Execute runs the command on the remote host over SSH.
func (e *SSHExecutor) Execute(ctx context.Context, cmd string) (string, error) {
	session, err := e.client.NewSession()
	if err != nil {
		return "", fmt.Errorf("failed to create SSH session: %w", err)
	}
	defer func() { _ = session.Close() }()

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	stdout := boundedio.NewBuffer(boundedio.StdoutLimit, cancel)
	stderr := boundedio.NewBuffer(boundedio.StderrLimit, cancel)
	session.Stdout = stdout
	session.Stderr = stderr

	// To properly support context cancellation via SSH, we run in a goroutine
	var runErr error
	done := make(chan struct{})
	go func() {
		runErr = session.Run(cmd)
		close(done)
	}()

	select {
	case <-ctx.Done():
		_ = session.Signal(ssh.SIGKILL)
		_ = session.Close()
		<-done
		if limitErr := errors.Join(stdout.Err(), stderr.Err()); limitErr != nil {
			return "", limitErr
		}
		return "", ctx.Err()
	case <-done:
		if limitErr := errors.Join(stdout.Err(), stderr.Err()); limitErr != nil {
			return "", limitErr
		}
		if runErr != nil {
			return "", fmt.Errorf("command execution failed: %w\nCommand: %s\nStderr: %s", runErr, cmd, strings.TrimSpace(stderr.String()))
		}
		return strings.TrimSpace(stdout.String()), nil
	}
}

// Close closes the underlying SSH connection and agent socket.
func (e *SSHExecutor) Close() error {
	var err error
	if e.client != nil {
		err = e.client.Close()
	}
	if e.agentConn != nil {
		if agentErr := e.agentConn.Close(); err == nil {
			err = agentErr
		}
	}
	return err
}
