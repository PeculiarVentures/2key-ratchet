package ratchet

import (
	"crypto/ecdh"
	"crypto/sha256"
	"io"

	"golang.org/x/crypto/hkdf"
)

// ─── Symmetric Ratchet (Chain) ───────────────────────────────────────────────

// SymmetricChain implements a sending or receiving chain.
// Matches SymmetricRatchet in 2key-ratchet/sym_ratchet.ts.
type SymmetricChain struct {
	// RootKey is the current chain key (HMAC key material, 32 bytes).
	// Named "rootKey" in the TS code (confusingly, this is the chain key,
	// NOT the ratchet root key).
	RootKey []byte
	Counter int
}

// Step advances the chain by one position and returns the cipher key material.
// Matches SymmetricRatchet.click() + calculateKey() in the TS code.
//
// calculateKey(rootKey):
//   cipherKeyBytes = HMAC(rootKey, [0x01])
//   nextRootKeyBytes = HMAC(rootKey, [0x02])
//   return { cipher: cipherKeyBytes, rootKey: importHMAC(nextRootKeyBytes) }
//
// click():
//   result = calculateKey(this.rootKey)
//   this.rootKey = result.rootKey
//   this.counter++
//   return result.cipher
func (c *SymmetricChain) Step() (cipherKey []byte, err error) {
	cipherKey = hmacSHA256(c.RootKey, cipherKeyKDFInput)
	nextRootKey := hmacSHA256(c.RootKey, rootKeyKDFInput)
	c.RootKey = nextRootKey
	c.Counter++
	return cipherKey, nil
}

// MessageKeys derives the AES key, HMAC key, and IV from a cipher key.
// Matches the HKDF call inside SendingRatchet.encrypt() / ReceivingRatchet.decrypt():
//   keys = HKDF(cipherKey, 3, null, "InfoMessageKeys")
//   aesKey = keys[0], hmacKey = keys[1], iv = keys[2][:16]
type MessageKeys struct {
	AESKey  []byte // 32 bytes, AES-256-CBC encryption key
	HMACKey []byte // 32 bytes, HMAC-SHA-256 signing key
	IV      []byte // 16 bytes, AES-CBC initialization vector
}

// DeriveMessageKeys derives message keys from a cipher key via HKDF.
func DeriveMessageKeys(cipherKey []byte) (*MessageKeys, error) {
	salt := make([]byte, 32)
	reader := hkdf.New(sha256.New, cipherKey, salt, infoMessageKeys)

	aesKey := make([]byte, 32)
	hmacKey := make([]byte, 32)
	ivMaterial := make([]byte, 32)

	if _, err := io.ReadFull(reader, aesKey); err != nil {
		return nil, err
	}
	if _, err := io.ReadFull(reader, hmacKey); err != nil {
		return nil, err
	}
	if _, err := io.ReadFull(reader, ivMaterial); err != nil {
		return nil, err
	}

	return &MessageKeys{
		AESKey:  aesKey,
		HMACKey: hmacKey,
		IV:      ivMaterial[:16],
	}, nil
}

// ─── DH Ratchet Step ─────────────────────────────────────────────────────────

// DHRatchetStep holds one step of the Diffie-Hellman ratchet.
type DHRatchetStep struct {
	RemoteRatchetKey *ecdh.PublicKey
	SendingChain     *SymmetricChain
	ReceivingChain   *SymmetricChain
}
