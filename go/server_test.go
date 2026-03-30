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

func TestProtocolIntegration(t *testing.T) {
	_, thisFile, _, _ := runtime.Caller(0)
	interopDir := filepath.Join(filepath.Dir(thisFile), "..", "interop")

	clientScript := filepath.Join(interopDir, "protocol_integration_test.js")
	if _, err := os.Stat(clientScript); err != nil {
		t.Skipf("protocol_integration_test.js not found: %v", err)
	}

	cert, err := GenerateSelfSignedCert()
	if err != nil {
		t.Fatalf("GenerateSelfSignedCert: %v", err)
	}

	// Match the TS server pattern: multiple signed pre-keys, no one-time pre-keys
	identity, err := GenerateIdentity(1, 10, 0)
	if err != nil {
		t.Fatalf("GenerateIdentity: %v", err)
	}

	config := ServerConfig{
		Address:  "127.0.0.1:31338",
		TLSCert:  cert,
		Identity: identity,
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

	t.Log("Starting Node.js protocol integration test...")
	cmd := exec.CommandContext(ctx, "node", clientScript, "127.0.0.1:31338")
	cmd.Dir = interopDir
	cmd.Env = append(os.Environ(), "NODE_TLS_REJECT_UNAUTHORIZED=0")
	output, err := cmd.CombinedOutput()
	t.Logf("Client output:\n%s", string(output))

	if err != nil {
		t.Fatalf("Node client failed: %v", err)
	}

	cancel()
}
