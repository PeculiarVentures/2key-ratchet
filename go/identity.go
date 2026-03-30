package ratchet

import (
	"crypto/ecdh"
	"fmt"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
)

// ─── Identity ────────────────────────────────────────────────────────────────

// Identity represents a party's long-term key material.
// Consists of a signing key pair (ECDSA P-256) and an exchange key pair (ECDH P-256).
type Identity struct {
	ID            int
	SigningKey    *ecdsa.PrivateKey
	ExchangeKey  *ecdh.PrivateKey
	PreKeys       []*ecdh.PrivateKey
	SignedPreKeys []*ecdh.PrivateKey
	CreatedAt     string
}

// GenerateIdentity creates a new identity with the specified pre-key counts.
// Set extractable=true for test usage (matches 2key-ratchet Identity.create()).
func GenerateIdentity(id int, signedPreKeyCount, preKeyCount int) (*Identity, error) {
	signingKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate signing key: %w", err)
	}

	exchangeKey, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate exchange key: %w", err)
	}

	preKeys := make([]*ecdh.PrivateKey, preKeyCount)
	for i := range preKeys {
		preKeys[i], err = ecdh.P256().GenerateKey(rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("generate pre-key %d: %w", i, err)
		}
	}

	signedPreKeys := make([]*ecdh.PrivateKey, signedPreKeyCount)
	for i := range signedPreKeys {
		signedPreKeys[i], err = ecdh.P256().GenerateKey(rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("generate signed pre-key %d: %w", i, err)
		}
	}

	return &Identity{
		ID:            id,
		SigningKey:    signingKey,
		ExchangeKey:  exchangeKey,
		PreKeys:       preKeys,
		SignedPreKeys: signedPreKeys,
	}, nil
}

// SigningPublicKeyRaw returns the uncompressed P-256 public key (65 bytes, 04||X||Y).
// This matches WebCrypto's exportKey("raw") for ECDSA keys.
func (id *Identity) SigningPublicKeyRaw() []byte {
	return elliptic.Marshal(id.SigningKey.Curve, id.SigningKey.PublicKey.X, id.SigningKey.PublicKey.Y)
}

// ExchangePublicKeyRaw returns the uncompressed ECDH public key bytes.
func (id *Identity) ExchangePublicKeyRaw() []byte {
	return id.ExchangeKey.PublicKey().Bytes()
}

// ─── Remote Identity ─────────────────────────────────────────────────────────

// RemoteIdentity represents a connected client's identity.
type RemoteIdentity struct {
	ID          int    `json:"id"`
	Thumbprint  string `json:"thumbprint"`
	SigningKey  []byte `json:"signingKey"`
	ExchangeKey []byte `json:"exchangeKey"`
	Signature   []byte `json:"signature"`
	CreatedAt   string `json:"createdAt"`
	UserAgent   string `json:"userAgent,omitempty"`
	Origin      string `json:"origin,omitempty"`
}

// Thumbprint computes the SHA-256 hex digest of a raw public key.
// Matches ECPublicKey.thumbprint() in 2key-ratchet.
//
// IMPORTANT: 2key-ratchet serializes EC public keys as X||Y (64 bytes),
// NOT the uncompressed point 04||X||Y (65 bytes) that WebCrypto exportKey("raw") returns.
// The thumbprint is SHA-256 of the X||Y form.
func Thumbprint(publicKeyRaw []byte) string {
	// If the input starts with 0x04 (uncompressed point), strip it
	xy := publicKeyRaw
	if len(xy) == 65 && xy[0] == 0x04 {
		xy = xy[1:] // X || Y, 64 bytes
	}
	h := sha256.Sum256(xy)
	return hex.EncodeToString(h[:])
}
