package ratchet

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

// TestCryptoActionIntegration starts the Go server with a stub CryptoProvider
// and runs the Node.js crypto action test against it.
//
// This tests the full stack: browser client SDK → ratchet transport →
// action dispatch → proto parsing → adapter → mock client → response encoding
func TestCryptoActionIntegration(t *testing.T) {
	_, thisFile, _, _ := runtime.Caller(0)
	interopDir := filepath.Join(filepath.Dir(thisFile), "..", "interop")

	clientScript := filepath.Join(interopDir, "crypto_action_test.js")
	if _, err := os.Stat(clientScript); err != nil {
		t.Skipf("crypto_action_test.js not found: %v", err)
	}

	cert, err := GenerateSelfSignedCert()
	if err != nil {
		t.Fatalf("GenerateSelfSignedCert: %v", err)
	}

	// Create mock adapter
	adapter := newStubProvider()

	config := ServerConfig{
		Address:        "127.0.0.1:31339",
		TLSCert:        cert,
		Identity:       nil, // auto-generate
		CryptoProvider: adapter,
		OnChallenge: func(pin string, origin string) bool {
			t.Logf("Challenge PIN: %s (auto-approved)", pin)
			return true
		},
	}

	server, err := NewWebCryptoServer(config)
	if err != nil {
		t.Fatalf("NewWebCryptoServer: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	serverErr := make(chan error, 1)
	go func() {
		serverErr <- server.ListenAndServe(ctx)
	}()
	time.Sleep(500 * time.Millisecond)

	t.Log("Starting Node.js crypto action test...")
	cmd := exec.CommandContext(ctx, "node", clientScript, "127.0.0.1:31339")
	cmd.Dir = interopDir
	cmd.Env = append(os.Environ(), "NODE_TLS_REJECT_UNAUTHORIZED=0")
	output, err := cmd.CombinedOutput()
	t.Logf("Client output:\n%s", string(output))

	if err != nil {
		t.Fatalf("Node crypto action test failed: %v", err)
	}

	cancel()
}
