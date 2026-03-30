package ratchet

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
)

// ─── AES-256-CBC ─────────────────────────────────────────────────────────────

// AESCBCEncrypt encrypts with AES-256-CBC and PKCS7 padding.
// Matches WebCrypto's AES-CBC encrypt.
func AESCBCEncrypt(key, iv, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("aes cipher: %w", err)
	}

	padded := pkcs7Pad(plaintext, aes.BlockSize)
	ciphertext := make([]byte, len(padded))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(ciphertext, padded)

	return ciphertext, nil
}

// AESCBCDecrypt decrypts with AES-256-CBC and removes PKCS7 padding.
func AESCBCDecrypt(key, iv, ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("aes cipher: %w", err)
	}

	if len(ciphertext)%aes.BlockSize != 0 {
		return nil, fmt.Errorf("ciphertext not multiple of block size")
	}

	plaintext := make([]byte, len(ciphertext))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(plaintext, ciphertext)

	return pkcs7Unpad(plaintext)
}

func pkcs7Pad(data []byte, blockSize int) []byte {
	padding := blockSize - (len(data) % blockSize)
	padded := make([]byte, len(data)+padding)
	copy(padded, data)
	for i := len(data); i < len(padded); i++ {
		padded[i] = byte(padding)
	}
	return padded
}

func pkcs7Unpad(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, ErrBadPadding
	}
	padding := int(data[len(data)-1])
	if padding > aes.BlockSize || padding == 0 {
		return nil, ErrBadPadding
	}
	for i := len(data) - padding; i < len(data); i++ {
		if data[i] != byte(padding) {
			return nil, ErrBadPadding
		}
	}
	return data[:len(data)-padding], nil
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

func hmacSHA256(key, data []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(data)
	return h.Sum(nil)
}

// ParseECDHPublicKey parses an uncompressed P-256 public key (65 bytes, 04||X||Y).
func ParseECDHPublicKey(raw []byte) (*ecdh.PublicKey, error) {
	return ecdh.P256().NewPublicKey(raw)
}

// ─── Serialization ───────────────────────────────────────────────────────────

type jsonIdentity struct {
	ID            int      `json:"id"`
	CreatedAt     string   `json:"createdAt"`
	SigningKey    string   `json:"signingKey"`    // DER hex
	ExchangeKey  string   `json:"exchangeKey"`   // raw hex
	PreKeys      []string `json:"preKeys"`       // raw hex
	SignedPreKeys []string `json:"signedPreKeys"` // raw hex
}

// MarshalJSON serializes the identity for persistence.
func (id *Identity) MarshalJSON() ([]byte, error) {
	sigDER, err := x509.MarshalECPrivateKey(id.SigningKey)
	if err != nil {
		return nil, err
	}

	ji := jsonIdentity{
		ID:          id.ID,
		CreatedAt:   id.CreatedAt,
		SigningKey:  hex.EncodeToString(sigDER),
		ExchangeKey: hex.EncodeToString(id.ExchangeKey.Bytes()),
	}

	for _, pk := range id.PreKeys {
		ji.PreKeys = append(ji.PreKeys, hex.EncodeToString(pk.Bytes()))
	}
	for _, spk := range id.SignedPreKeys {
		ji.SignedPreKeys = append(ji.SignedPreKeys, hex.EncodeToString(spk.Bytes()))
	}

	return json.Marshal(ji)
}

// UnmarshalJSON restores a persisted identity.
func (id *Identity) UnmarshalJSON(data []byte) error {
	var ji jsonIdentity
	if err := json.Unmarshal(data, &ji); err != nil {
		return err
	}

	sigDER, err := hex.DecodeString(ji.SigningKey)
	if err != nil {
		return fmt.Errorf("decode signing key: %w", err)
	}
	sigKey, err := x509.ParseECPrivateKey(sigDER)
	if err != nil {
		return fmt.Errorf("parse signing key: %w", err)
	}

	exBytes, err := hex.DecodeString(ji.ExchangeKey)
	if err != nil {
		return fmt.Errorf("decode exchange key: %w", err)
	}
	exKey, err := ecdh.P256().NewPrivateKey(exBytes)
	if err != nil {
		return fmt.Errorf("parse exchange key: %w", err)
	}

	id.ID = ji.ID
	id.CreatedAt = ji.CreatedAt
	id.SigningKey = sigKey
	id.ExchangeKey = exKey

	id.PreKeys = make([]*ecdh.PrivateKey, len(ji.PreKeys))
	for i, pkHex := range ji.PreKeys {
		pkBytes, err := hex.DecodeString(pkHex)
		if err != nil {
			return fmt.Errorf("decode pre-key %d: %w", i, err)
		}
		id.PreKeys[i], err = ecdh.P256().NewPrivateKey(pkBytes)
		if err != nil {
			return fmt.Errorf("parse pre-key %d: %w", i, err)
		}
	}

	id.SignedPreKeys = make([]*ecdh.PrivateKey, len(ji.SignedPreKeys))
	for i, spkHex := range ji.SignedPreKeys {
		spkBytes, err := hex.DecodeString(spkHex)
		if err != nil {
			return fmt.Errorf("decode signed pre-key %d: %w", i, err)
		}
		id.SignedPreKeys[i], err = ecdh.P256().NewPrivateKey(spkBytes)
		if err != nil {
			return fmt.Errorf("parse signed pre-key %d: %w", i, err)
		}
	}

	return nil
}

