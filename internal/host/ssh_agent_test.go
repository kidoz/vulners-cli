package host

import (
	"crypto/ed25519"
	"crypto/rand"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

func TestLoadAgentSignersKeepsConnectionUsable(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix agent socket is not available on Windows")
	}
	keyring := agent.NewKeyring()
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := keyring.Add(agent.AddedKey{PrivateKey: privateKey}); err != nil {
		t.Fatal(err)
	}

	dir, err := os.MkdirTemp("/tmp", "vulners-agent-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	socket := filepath.Join(dir, "a.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = listener.Close() }()
	go func() {
		for {
			conn, acceptErr := listener.Accept()
			if acceptErr != nil {
				return
			}
			go func() { _ = agent.ServeAgent(keyring, conn) }()
		}
	}()

	signers, conn := loadAgentSigners(socket)
	if conn == nil || len(signers) != 1 {
		t.Fatalf("loadAgentSigners() returned %d signers, connection %v", len(signers), conn)
	}
	defer func() { _ = conn.Close() }()
	if _, err := signers[0].Sign(rand.Reader, []byte("test payload")); err != nil {
		t.Fatalf("agent signer could not sign after loading: %v", err)
	}
	if _, err := ssh.ParsePublicKey(signers[0].PublicKey().Marshal()); err != nil {
		t.Fatalf("invalid signer public key: %v", err)
	}
}
