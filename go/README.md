# 2key-ratchet / Go

Go implementation of the [2key-ratchet](https://github.com/PeculiarVentures/2key-ratchet) Double Ratchet + X3DH protocol, byte-level compatible with the TypeScript v1.0.18 implementation.

## Files

### Protocol

- **doc.go** -- Package documentation, error types, protocol constants
- **identity.go** -- Identity key generation, signing/exchange key pairs, thumbprint
- **x3dh.go** -- X3DH key agreement (AuthenticateA/B), root key derivation, challenge PIN
- **chain.go** -- Symmetric ratchet chain, message key derivation via HKDF
- **session.go** -- Session management, encrypt/decrypt with MAC-then-decrypt ordering, DH ratchet advancement, skipped key cache with TTL expiry
- **crypto.go** -- AES-256-CBC, PKCS7 padding, HMAC-SHA-256, identity serialization

### Wire format

- **wire.go** -- Protobuf encoding/decoding for PreKeyBundle, PreKeyMessage, MessageSignedProtocol. ECDSA P-256 SHA-512 signature verification with P1363/DER conversion.

### Transport

- **server.go** -- WebSocket server implementing the webcrypto-socket transport. Handles well-known endpoint (PreKeyBundle distribution), 2key-ratchet session handshake, challenge PIN authentication, origin checking, message size limits, and action routing via CryptoProvider or OnAction callback.
- **actions.go** -- Parses all 38 webcrypto-local action types and routes them to the CryptoProvider interface. Defines the CryptoProvider interface that applications implement to handle WebCrypto operations (sign, verify, encrypt, decrypt, key storage, certificate storage, etc).
- **tlscert.go** -- Self-signed TLS certificate generation for the WSS endpoint.

## Tests

43 tests, 0 fail.

- **ratchet_test.go** -- 22 standalone protocol tests with hardcoded reference vectors from the TS implementation
- **interop_test.go** -- 10 cross-language interop tests validating every intermediate value against TS-generated vectors in `../interop/vectors.json`
- **server_test.go** -- Live integration test: actual TS webcrypto-socket client SDK connects to the Go server over WSS, completes the full ratchet handshake, and exchanges encrypted action messages
- **dispatch_test.go** -- 9 tests exercising the full dispatch path through CryptoProvider (proto construction, DispatchAction, response encoding)
- **crypto_action_integration_test.go** -- End-to-end test using the actual TS client SDK against the Go server with a stub CryptoProvider, exercising keyStorage.keys, getItem, subtle.sign, exportKey, certStorage, indexOf, and digest

## Running

```bash
# All tests including live TS integration
cd interop && npm install && cd ../go && go test -v ./...

# Protocol tests only (no Node.js needed)
go test -v -run 'Test[^P]' ./...
```

## Dependencies

- `golang.org/x/crypto` (HKDF)
- `github.com/gorilla/websocket` (WebSocket server)

## CryptoProvider interface

Applications implement the CryptoProvider interface to handle WebCrypto operations from browser clients. The server parses incoming action protos and dispatches them to the appropriate method.

```go
type MyCryptoProvider struct { /* ... */ }

func (p *MyCryptoProvider) Sign(providerID string, algorithm *ratchet.ParsedAlgorithm, key *ratchet.ParsedCryptoKey, data []byte) ([]byte, error) {
    // Sign data with the key identified by key.ID
}

func (p *MyCryptoProvider) KeyStorageKeys(providerID string) ([]byte, error) {
    // Return comma-separated key IDs
}

// ... implement all CryptoProvider methods (see actions.go for the full interface)

server, _ := ratchet.NewWebCryptoServer(ratchet.ServerConfig{
    Address:        "127.0.0.1:31337",
    TLSCert:        tlsCert,
    CryptoProvider: &MyCryptoProvider{},
    OnChallenge: func(pin, origin string) bool {
        return showPINDialog(pin, origin)
    },
})
server.ListenAndServe(ctx)
```

For actions not handled by CryptoProvider, or if CryptoProvider is nil, the server falls back to the OnAction callback.

## Known limitations

These behaviors match the TS implementation and are by design.

**Session state is in-memory only.** Sessions are not persisted to disk. A server restart terminates all active ratchet sessions and clients must reconnect and re-handshake. Identity keys can be persisted separately via `Identity.MarshalJSON` / `Identity.UnmarshalJSON` to maintain a stable server identity across restarts.

**PreKeyBundle does not include one-time pre-keys.** The server caches a single PreKeyBundle at startup containing only the signed pre-key. One-time pre-keys (OPKs) are generated but never included in the bundle, matching the TS server's `getRandomBundle()` behavior. This means X3DH uses three DH computations (DH1, DH2, DH3) instead of four. The security impact is that compromise of the signed pre-key's private key allows an attacker to compute past session keys. OPK support would require per-request bundle generation and one-time key consumption tracking.

**Skipped key cache is bounded by count and time.** Out-of-order messages are handled by caching skipped message keys. The cache is bounded by `MaxSkip` (1000 entries) and `DefaultSkippedKeyTTL` (1 hour). Keys older than the TTL are pruned on each decrypt operation. A long-lived session that receives no messages for over an hour will lose any cached skipped keys for that period.

## Protocol compatibility notes

Behaviors verified through cross-language interop testing against the TS implementation.

1. Thumbprint hashes X||Y (64 bytes), not 04||X||Y. The TS `ECPublicKey.serialize()` strips the uncompressed point prefix before hashing.
2. X3DH KM has a 32-byte 0xFF prefix. `KM = FF(32) || DH1 || DH2 || DH3 || DH4`.
3. Challenge PIN uses JavaScript float64 scientific notation. `parseInt(hexDigest, 16)` produces a float64 string, and `.substr(2, 6)` extracts from that representation.
4. Chain KDF uses two separate HMACs, not HKDF. `cipherKey = HMAC(chainKey, [0x01])`, `nextChainKey = HMAC(chainKey, [0x02])`.
5. ECDSA uses SHA-512 not SHA-256. Signatures are P1363 format, not DER.
6. MAC-then-decrypt ordering. HMAC is verified before AES-CBC decryption. If signing keys are not set on the session, decryption returns an error rather than silently skipping verification.

## Crypto primitives

All from Go standard library and `golang.org/x/crypto`.

| Operation | Go package |
|---|---|
| ECDH P-256 | `crypto/ecdh` |
| ECDSA P-256 SHA-512 | `crypto/ecdsa` |
| AES-256-CBC | `crypto/aes` + `crypto/cipher` |
| HMAC-SHA-256 | `crypto/hmac` + `crypto/sha256` |
| HKDF-SHA-256 | `golang.org/x/crypto/hkdf` |
| SHA-256 | `crypto/sha256` |
