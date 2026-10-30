package host

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/kidoz/vulners-cli/internal/boundedio"
	"golang.org/x/crypto/ssh"
)

func TestSSHExecutor_OutputLimit(t *testing.T) {
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(key)
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = listener.Close() }()
	go serveOversizedSSHOutput(listener, signer)
	client, err := ssh.Dial("tcp", listener.Addr().String(), &ssh.ClientConfig{User: "test", HostKeyCallback: ssh.FixedHostKey(signer.PublicKey()), Timeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	executor := &SSHExecutor{client: client}
	defer func() { _ = executor.Close() }()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	out, err := executor.Execute(ctx, "inventory")
	if !errors.Is(err, boundedio.ErrOutputLimit) || out != "" {
		t.Fatalf("expected overflow without partial output, got %q, %v", out, err)
	}
}

func serveOversizedSSHOutput(listener net.Listener, signer ssh.Signer) {
	conn, err := listener.Accept()
	if err != nil {
		return
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	config := &ssh.ServerConfig{NoClientAuth: true}
	config.AddHostKey(signer)
	server, channels, requests, err := ssh.NewServerConn(conn, config)
	if err != nil {
		return
	}
	defer func() { _ = server.Close() }()
	go ssh.DiscardRequests(requests)
	newChannel, ok := <-channels
	if !ok {
		return
	}
	channel, commands, err := newChannel.Accept()
	if err != nil {
		return
	}
	defer func() { _ = channel.Close() }()
	request, ok := <-commands
	if !ok {
		return
	}
	_ = request.Reply(true, nil)
	go ssh.DiscardRequests(commands)
	chunk := bytes.Repeat([]byte("x"), 32<<10)
	for {
		if _, err := channel.Stderr().Write(chunk); err != nil {
			return
		}
	}
}
