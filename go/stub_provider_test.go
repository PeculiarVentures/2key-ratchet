package ratchet

// stubProvider is a minimal CryptoProvider for testing action dispatch.
// It stores keys and certs in memory and returns predictable results.

import (
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"strings"
	"sync"
)

type stubKey struct {
	ID        string
	Name      string
	Type      string
	Algorithm string
	Usages    []string
}

type stubCert struct {
	ID    string
	Name  string
	KeyID string
	DER   []byte
}

type stubProvider struct {
	mu       sync.RWMutex
	keys     []stubKey
	certs    []stubCert
	memKeys  map[string]*stubKey  // memoryID → key
	memCerts map[string]*stubCert // memoryID → cert
}

var testCertDER []byte

func init() {
	cert, err := GenerateSelfSignedCert()
	if err != nil {
		panic(err)
	}
	testCertDER = cert.Certificate[0]
}

func newStubProvider() *stubProvider {
	return &stubProvider{
		keys: []stubKey{
			{ID: "key-001", Name: "TestRSA", Type: "RSA", Algorithm: "RSASSA-PKCS1-v1_5", Usages: []string{"AUTH"}},
			{ID: "key-002", Name: "TestEC", Type: "EC", Algorithm: "ECDSA", Usages: []string{"AUTH"}},
		},
		certs: []stubCert{
			{ID: "cert-001", Name: "TestCert", KeyID: "key-001", DER: testCertDER},
		},
		memKeys:  make(map[string]*stubKey),
		memCerts: make(map[string]*stubCert),
	}
}

func (p *stubProvider) memID(providerID, itemType, rawID string) string {
	h := sha256.Sum256([]byte(providerID + "0" + "0" + itemType + rawID))
	return hex.EncodeToString(h[:])
}

func (p *stubProvider) GetCrypto(providerID string) ([]byte, error) {
	return []byte{0x08, 0x01}, nil
}

func (p *stubProvider) Sign(providerID string, algorithm *ParsedAlgorithm, key *ParsedCryptoKey, data []byte) ([]byte, error) {
	if _, err := p.resolveKey(key); err != nil {
		return nil, err
	}
	return []byte{0xDE, 0xAD}, nil // stub signature
}

func (p *stubProvider) Verify(providerID string, algorithm *ParsedAlgorithm, key *ParsedCryptoKey, data, signature []byte) (bool, error) {
	return true, nil
}

func (p *stubProvider) Encrypt(providerID string, algorithm *ParsedAlgorithm, key *ParsedCryptoKey, data []byte) ([]byte, error) {
	return data, nil // stub: return data unchanged
}

func (p *stubProvider) Decrypt(providerID string, algorithm *ParsedAlgorithm, key *ParsedCryptoKey, data []byte) ([]byte, error) {
	return data, nil
}

func (p *stubProvider) Digest(providerID string, algorithm *ParsedAlgorithm, data []byte) ([]byte, error) {
	if algorithm == nil {
		return nil, fmt.Errorf("algorithm required")
	}
	switch algorithm.Name {
	case "SHA-1":
		h := sha1.Sum(data)
		return h[:], nil
	case "SHA-256":
		h := sha256.Sum256(data)
		return h[:], nil
	case "SHA-384":
		h := sha512.Sum384(data)
		return h[:], nil
	case "SHA-512":
		h := sha512.Sum512(data)
		return h[:], nil
	default:
		return nil, fmt.Errorf("unsupported: %s", algorithm.Name)
	}
}

func (p *stubProvider) GenerateKey(providerID string, algorithm *ParsedAlgorithm, extractable bool, usages []string) ([]byte, error) {
	return nil, fmt.Errorf("generateKey not supported")
}

func (p *stubProvider) ExportKey(providerID string, format string, key *ParsedCryptoKey) ([]byte, error) {
	if _, err := p.resolveKey(key); err != nil {
		return nil, err
	}
	return []byte{1, 2, 3}, nil // stub SPKI
}

func (p *stubProvider) ImportKey(providerID string, format string, keyData []byte, algorithm *ParsedAlgorithm, extractable bool, usages []string) ([]byte, error) {
	return nil, fmt.Errorf("importKey not supported")
}

func (p *stubProvider) KeyStorageKeys(providerID string) ([]byte, error) {
	var ids []string
	for _, k := range p.keys {
		safeName := strings.ReplaceAll(k.Name, "-", "_")
		ids = append(ids, fmt.Sprintf("private-%s-%s", safeName, k.ID))
		ids = append(ids, fmt.Sprintf("public-%s-%s", safeName, k.ID))
	}
	return []byte(strings.Join(ids, ",")), nil
}

func (p *stubProvider) KeyStorageGetItem(providerID string, keyID string, algorithm *ParsedAlgorithm, extractable bool, usages []string) ([]byte, error) {
	// Parse PKCS#11-style label
	parts := strings.SplitN(keyID, "-", 3)
	var keyType, rawID string
	if len(parts) == 3 {
		keyType = parts[0]
		rawID = parts[2]
	} else {
		keyType = "private"
		rawID = keyID
	}

	var found *stubKey
	for i := range p.keys {
		if p.keys[i].ID == rawID {
			found = &p.keys[i]
			break
		}
	}
	if found == nil {
		return nil, fmt.Errorf("key not found: %s", keyID)
	}

	memID := p.memID(providerID, keyType, rawID)
	p.mu.Lock()
	p.memKeys[memID] = found
	p.mu.Unlock()

	idBytes, _ := hex.DecodeString(memID)

	// Build CryptoKeyProto (webcrypto-local field IDs)
	var algBuf []byte
	algBuf = append(algBuf, pbUint32Field(1, 1)...)
	algBuf = append(algBuf, pbBytesField(2, []byte(found.Algorithm))...)

	var buf []byte
	buf = append(buf, pbUint32Field(1, 1)...)
	buf = append(buf, pbBytesField(2, []byte(providerID))...)
	buf = append(buf, pbBytesField(3, idBytes)...)
	buf = append(buf, pbBytesField(4, []byte(keyType))...)
	buf = append(buf, pbBytesField(5, algBuf)...)
	buf = append(buf, pbUint32Field(6, 0)...)
	for _, u := range found.Usages {
		if u == "AUTH" {
			buf = append(buf, pbBytesField(7, []byte("sign"))...)
			buf = append(buf, pbBytesField(7, []byte("verify"))...)
		}
	}
	return buf, nil
}

func (p *stubProvider) KeyStorageSetItem(providerID string, key *ParsedCryptoKey) ([]byte, error) {
	return nil, fmt.Errorf("not supported")
}

func (p *stubProvider) KeyStorageRemoveItem(providerID string, keyID string) error {
	return fmt.Errorf("not supported")
}

func (p *stubProvider) KeyStorageIndexOf(providerID string, key *ParsedCryptoKey) ([]byte, error) {
	sk, err := p.resolveKey(key)
	if err != nil {
		return nil, nil
	}
	safeName := strings.ReplaceAll(sk.Name, "-", "_")
	p.mu.RLock()
	var itemType string
	memID := hex.EncodeToString(key.ID)
	if item, ok := p.memKeys[memID]; ok && item != nil {
		// Find the type from the memory entry
		for t, candidate := range map[string]string{"private": sk.ID, "public": sk.ID} {
			if p.memID(providerID, t, candidate) == memID {
				itemType = t
				break
			}
		}
	}
	p.mu.RUnlock()
	if itemType == "" {
		itemType = "private"
	}
	return []byte(fmt.Sprintf("%s-%s-%s", itemType, safeName, sk.ID)), nil
}

func (p *stubProvider) CertStorageKeys(providerID string) ([]byte, error) {
	var ids []string
	for _, c := range p.certs {
		safeName := strings.ReplaceAll(c.Name, "-", "_")
		sharedID := c.KeyID
		if sharedID == "" {
			sharedID = c.ID
		}
		ids = append(ids, fmt.Sprintf("x509-%s-%s", safeName, sharedID))
	}
	return []byte(strings.Join(ids, ",")), nil
}

func (p *stubProvider) CertStorageGetItem(providerID string, certID string, algorithm *ParsedAlgorithm, usages []string) ([]byte, error) {
	parts := strings.SplitN(certID, "-", 3)
	var sharedID string
	if len(parts) == 3 {
		sharedID = parts[2]
	} else {
		sharedID = certID
	}

	var found *stubCert
	for i := range p.certs {
		sid := p.certs[i].KeyID
		if sid == "" {
			sid = p.certs[i].ID
		}
		if sid == sharedID || p.certs[i].ID == sharedID {
			found = &p.certs[i]
			break
		}
	}
	if found == nil {
		return nil, fmt.Errorf("certificate not found: %s", certID)
	}

	certMemID := p.memID(providerID, "x509", found.ID)
	idBytes, _ := hex.DecodeString(certMemID)
	pubKeyMemID := p.memID(providerID, "public", sharedID)
	pubIDBytes, _ := hex.DecodeString(pubKeyMemID)

	// Nested public key proto
	var pubBuf []byte
	pubBuf = append(pubBuf, pbUint32Field(1, 1)...)
	pubBuf = append(pubBuf, pbBytesField(2, []byte(providerID))...)
	pubBuf = append(pubBuf, pbBytesField(3, pubIDBytes)...)
	pubBuf = append(pubBuf, pbBytesField(4, []byte("public"))...)

	// CryptoX509CertificateProto
	var buf []byte
	buf = append(buf, pbUint32Field(1, 1)...)
	buf = append(buf, pbBytesField(2, []byte(providerID))...)
	buf = append(buf, pbBytesField(3, idBytes)...)
	buf = append(buf, pbBytesField(4, []byte("x509"))...)
	buf = append(buf, pbBytesField(5, idBytes)...)
	buf = append(buf, pbBytesField(6, pubBuf)...)
	buf = append(buf, pbBytesField(7, []byte("x509"))...)
	buf = append(buf, pbBytesField(8, []byte(""))...)
	buf = append(buf, pbUint32Field(9, 0)...)
	buf = append(buf, pbUint32Field(10, 0)...)
	buf = append(buf, pbBytesField(11, []byte{0x01})...)
	buf = append(buf, pbBytesField(12, []byte("CN=Test"))...)
	buf = append(buf, pbBytesField(13, []byte("CN=Test"))...)
	buf = append(buf, pbBytesField(14, []byte("2025-01-01T00:00:00.000Z"))...)
	buf = append(buf, pbBytesField(15, []byte("2026-01-01T00:00:00.000Z"))...)

	return buf, nil
}

func (p *stubProvider) CertStorageSetItem(providerID string, data []byte) ([]byte, error) {
	return nil, fmt.Errorf("not supported")
}
func (p *stubProvider) CertStorageRemoveItem(providerID string, certID string) error {
	return fmt.Errorf("not supported")
}
func (p *stubProvider) CertStorageImport(providerID string, format string, data []byte, algorithm *ParsedAlgorithm, usages []string) ([]byte, error) {
	return nil, fmt.Errorf("not supported")
}
func (p *stubProvider) CertStorageExport(providerID string, format string, item []byte) ([]byte, error) {
	return nil, fmt.Errorf("not supported")
}
func (p *stubProvider) CertStorageIndexOf(providerID string, item []byte) ([]byte, error) {
	return nil, nil
}
func (p *stubProvider) CertStorageGetChain(providerID string, item []byte) ([]byte, error) {
	return nil, fmt.Errorf("not supported")
}
func (p *stubProvider) CertStorageGetValue(providerID string, certID string) ([]byte, error) {
	return nil, fmt.Errorf("not supported")
}
func (p *stubProvider) CertStorageGetCRL(providerID string, url string) ([]byte, error) {
	return nil, fmt.Errorf("not supported")
}
func (p *stubProvider) CertStorageGetOCSP(providerID string, url string, request []byte) ([]byte, error) {
	return nil, fmt.Errorf("not supported")
}
func (p *stubProvider) CryptoLogin(providerID string) error            { return nil }
func (p *stubProvider) CryptoLogout(providerID string) error           { return nil }
func (p *stubProvider) CryptoIsLoggedIn(providerID string) (bool, error) { return true, nil }
func (p *stubProvider) CryptoReset(providerID string) error            { return nil }
func (p *stubProvider) DeriveBits(providerID string, algorithm *ParsedAlgorithm, key *ParsedCryptoKey, length int) ([]byte, error) {
	return nil, fmt.Errorf("not supported")
}
func (p *stubProvider) DeriveKey(providerID string, algorithm *ParsedAlgorithm, key *ParsedCryptoKey, derivedKeyType *ParsedAlgorithm, extractable bool, usages []string) ([]byte, error) {
	return nil, fmt.Errorf("not supported")
}
func (p *stubProvider) WrapKey(providerID string, format string, key *ParsedCryptoKey, wrappingKey *ParsedCryptoKey, wrapAlgorithm *ParsedAlgorithm) ([]byte, error) {
	return nil, fmt.Errorf("not supported")
}
func (p *stubProvider) UnwrapKey(providerID string, format string, wrappedKey []byte, unwrappingKey *ParsedCryptoKey, unwrapAlgorithm *ParsedAlgorithm, unwrappedKeyAlgorithm *ParsedAlgorithm, extractable bool, usages []string) ([]byte, error) {
	return nil, fmt.Errorf("not supported")
}

// resolveKey finds the stub key from a ParsedCryptoKey's memory ID.
func (p *stubProvider) resolveKey(key *ParsedCryptoKey) (*stubKey, error) {
	if key == nil || len(key.ID) == 0 {
		return nil, fmt.Errorf("key is nil or empty")
	}
	memID := hex.EncodeToString(key.ID)
	p.mu.RLock()
	sk := p.memKeys[memID]
	p.mu.RUnlock()
	if sk != nil {
		return sk, nil
	}
	return nil, fmt.Errorf("key not found in memory: %s", memID)
}
