package ratchet

// Action dispatch for the webcrypto-local protocol.
//
// Parses all 38 webcrypto-local action types and routes them to the
// CryptoProvider interface. This is the layer between the WebSocket
// transport (server.go) and the application's key management backend.
//
// The CryptoProvider interface defines the operations that applications
// implement to handle WebCrypto calls from browser clients.
//
// Field ID convention: webcrypto-local protos use BaseProto.INDEX=1
// (version at field 1), unlike the 2key-ratchet protocol messages
// which use field 0 for version. All action proto field IDs are
// offset by +1 from what a naive reading of the TS source might suggest.
//
// Each browser WebCrypto call arrives as an encrypted protobuf action.
// This file parses those protos and dispatches to a CryptoProvider
// interface that the host application implements.
//
// Protobuf field IDs (inheritance chain):
//
//   BaseProto:     version=0
//   ActionProto:   action=1, actionId=2          (INDEX=3)
//   CryptoAction:  providerID=3                  (INDEX=4)
//   SignAction:    algorithm=4, key=5, data=6    (INDEX=7)
//   VerifyAction:  signature=7                   (INDEX=8)
//   ExportKey:     format=4, key=5               (INDEX=6)
//   ImportKey:     format=4, keyData=5, algorithm=6, extractable=7, keyUsages=8
//   GenerateKey:   algorithm=4, extractable=5, usage=6
//   DigestAction:  algorithm=4, data=5
//   EncryptAction: algorithm=4, key=5, data=6    (same as Sign)
//   DecryptAction: algorithm=4, key=5, data=6    (same as Sign)
//
//   CryptoItemProto:  providerID=1, id=2, type=3  (INDEX=4)
//   CryptoKeyProto:   algorithm=4, extractable=5, usages=6
//
//   BaseAlgorithmProto: name=1                    (INDEX=2)
//   AlgorithmProto:     hash=2, ...

import (
	"fmt"
)

// ─── Parsed Action Types ─────────────────────────────────────────────────────

// ParsedAction holds the common fields from any ActionProto.
type ParsedAction struct {
	Version    uint32
	Action     string
	ActionID   string
	ProviderID string // for CryptoActionProto (field 3)
}

// ParsedAlgorithm holds the parsed fields from AlgorithmProto.
type ParsedAlgorithm struct {
	Name string
	Hash *ParsedAlgorithm // nested hash algorithm (e.g., {name: "SHA-256"})
	// Raw bytes for algorithm-specific fields we don't parse yet
	RawFields []pbFieldVal
}

// ParsedCryptoKey holds the parsed fields from CryptoKeyProto.
type ParsedCryptoKey struct {
	ProviderID  string
	ID          []byte // hex-encoded key identifier
	Type        string // "public", "private", "secret"
	Algorithm   *ParsedAlgorithm
	Extractable bool
	Usages      []string
}

// ParsedSignAction holds crypto/subtle/sign fields.
type ParsedSignAction struct {
	ParsedAction
	Algorithm *ParsedAlgorithm
	Key       *ParsedCryptoKey
	Data      []byte
}

// ParsedVerifyAction holds crypto/subtle/verify fields.
type ParsedVerifyAction struct {
	ParsedSignAction
	Signature []byte
}

// ParsedExportKeyAction holds crypto/subtle/exportKey fields.
type ParsedExportKeyAction struct {
	ParsedAction
	Format string
	Key    *ParsedCryptoKey
}

// ParsedImportKeyAction holds crypto/subtle/importKey fields.
type ParsedImportKeyAction struct {
	ParsedAction
	Format      string
	KeyData     []byte
	Algorithm   *ParsedAlgorithm
	Extractable bool
	KeyUsages   []string
}

// ParsedGenerateKeyAction holds crypto/subtle/generateKey fields.
type ParsedGenerateKeyAction struct {
	ParsedAction
	Algorithm   *ParsedAlgorithm
	Extractable bool
	Usages      []string
}

// ParsedDigestAction holds crypto/subtle/digest fields.
type ParsedDigestAction struct {
	ParsedAction
	Algorithm *ParsedAlgorithm
	Data      []byte
}

// ParsedEncryptAction holds crypto/subtle/encrypt or decrypt fields.
type ParsedEncryptAction = ParsedSignAction

// ParsedKeyStorageAction holds crypto/keyStorage/* fields.
type ParsedKeyStorageAction struct {
	ParsedAction
	Key         string           // key ID for getItem/removeItem
	Item        *ParsedCryptoKey // for setItem
	Algorithm   *ParsedAlgorithm // for getItem
	Extractable bool             // for getItem
	KeyUsages   []string         // for getItem
}

// ParsedCertStorageAction holds crypto/certificateStorage/* fields.
type ParsedCertStorageAction struct {
	ParsedAction
	Key       string           // cert ID for getItem/removeItem
	Item      []byte           // for setItem/import (raw cert bytes)
	Format    string           // for import/export
	Algorithm *ParsedAlgorithm // for getItem/import
	KeyUsages []string         // for getItem/import
	Data      []byte           // for import
}

// ─── Parsers ─────────────────────────────────────────────────────────────────

// ParseAction extracts the common ActionProto fields from raw bytes.
func ParseAction(data []byte) (*ParsedAction, error) {
	fields, err := pbParseAll(data)
	if err != nil {
		return nil, err
	}
	a := &ParsedAction{}
	for _, f := range fields {
		switch f.fieldNum {
		case 1:
			a.Version = uint32(f.varint)
		case 2:
			a.Action = string(f.bytes)
		case 3:
			a.ActionID = string(f.bytes)
		case 4:
			// ProviderID for CryptoActionProto, cryptoID for getCrypto
			a.ProviderID = string(f.bytes)
		}
	}
	return a, nil
}

// ParseAlgorithm extracts an AlgorithmProto from raw bytes.
func ParseAlgorithm(data []byte) (*ParsedAlgorithm, error) {
	fields, err := pbParseAll(data)
	if err != nil {
		return nil, err
	}
	a := &ParsedAlgorithm{}
	for _, f := range fields {
		switch f.fieldNum {
		case 2:
			a.Name = string(f.bytes)
		case 3:
			if f.wireType == 2 && len(f.bytes) > 0 {
				hash, err := ParseAlgorithm(f.bytes)
				if err == nil {
					a.Hash = hash
				}
			}
		default:
			a.RawFields = append(a.RawFields, f)
		}
	}
	return a, nil
}

// ParseCryptoKey extracts a CryptoKeyProto from raw bytes.
func ParseCryptoKey(data []byte) (*ParsedCryptoKey, error) {
	fields, err := pbParseAll(data)
	if err != nil {
		return nil, err
	}
	k := &ParsedCryptoKey{}
	for _, f := range fields {
		switch f.fieldNum {
		case 2:
			k.ProviderID = string(f.bytes)
		case 3:
			k.ID = f.bytes
		case 4:
			k.Type = string(f.bytes)
		case 5:
			if f.wireType == 2 {
				alg, err := ParseAlgorithm(f.bytes)
				if err == nil {
					k.Algorithm = alg
				}
			}
		case 6:
			k.Extractable = f.varint != 0
		case 7:
			k.Usages = append(k.Usages, string(f.bytes))
		}
	}
	return k, nil
}

// ParseSignAction parses crypto/subtle/sign, encrypt, or decrypt.
func ParseSignAction(data []byte) (*ParsedSignAction, error) {
	fields, err := pbParseAll(data)
	if err != nil {
		return nil, err
	}
	a := &ParsedSignAction{}
	for _, f := range fields {
		switch f.fieldNum {
		case 1:
			a.Version = uint32(f.varint)
		case 2:
			a.Action = string(f.bytes)
		case 3:
			a.ActionID = string(f.bytes)
		case 4:
			a.ProviderID = string(f.bytes)
		case 5:
			if f.wireType == 2 {
				alg, err := ParseAlgorithm(f.bytes)
				if err == nil {
					a.Algorithm = alg
				}
			}
		case 6:
			if f.wireType == 2 {
				key, err := ParseCryptoKey(f.bytes)
				if err == nil {
					a.Key = key
				}
			}
		case 7:
			a.Data = f.bytes
		}
	}
	return a, nil
}

// ParseVerifyAction parses crypto/subtle/verify.
func ParseVerifyAction(data []byte) (*ParsedVerifyAction, error) {
	sign, err := ParseSignAction(data)
	if err != nil {
		return nil, err
	}
	fields, err := pbParseAll(data)
	if err != nil {
		return nil, err
	}
	v := &ParsedVerifyAction{ParsedSignAction: *sign}
	for _, f := range fields {
		if f.fieldNum == 7 {
			v.Signature = f.bytes
		}
	}
	return v, nil
}

// ParseExportKeyAction parses crypto/subtle/exportKey.
func ParseExportKeyAction(data []byte) (*ParsedExportKeyAction, error) {
	fields, err := pbParseAll(data)
	if err != nil {
		return nil, err
	}
	a := &ParsedExportKeyAction{}
	for _, f := range fields {
		switch f.fieldNum {
		case 1:
			a.Version = uint32(f.varint)
		case 2:
			a.Action = string(f.bytes)
		case 3:
			a.ActionID = string(f.bytes)
		case 4:
			a.ProviderID = string(f.bytes)
		case 5:
			a.Format = string(f.bytes)
		case 6:
			if f.wireType == 2 {
				key, err := ParseCryptoKey(f.bytes)
				if err == nil {
					a.Key = key
				}
			}
		}
	}
	return a, nil
}

// ParseGenerateKeyAction parses crypto/subtle/generateKey.
func ParseGenerateKeyAction(data []byte) (*ParsedGenerateKeyAction, error) {
	fields, err := pbParseAll(data)
	if err != nil {
		return nil, err
	}
	a := &ParsedGenerateKeyAction{}
	for _, f := range fields {
		switch f.fieldNum {
		case 1:
			a.Version = uint32(f.varint)
		case 2:
			a.Action = string(f.bytes)
		case 3:
			a.ActionID = string(f.bytes)
		case 4:
			a.ProviderID = string(f.bytes)
		case 5:
			if f.wireType == 2 {
				alg, err := ParseAlgorithm(f.bytes)
				if err == nil {
					a.Algorithm = alg
				}
			}
		case 6:
			a.Extractable = f.varint != 0
		case 7:
			a.Usages = append(a.Usages, string(f.bytes))
		}
	}
	return a, nil
}

// ParseDigestAction parses crypto/subtle/digest.
func ParseDigestAction(data []byte) (*ParsedDigestAction, error) {
	fields, err := pbParseAll(data)
	if err != nil {
		return nil, err
	}
	a := &ParsedDigestAction{}
	for _, f := range fields {
		switch f.fieldNum {
		case 1:
			a.Version = uint32(f.varint)
		case 2:
			a.Action = string(f.bytes)
		case 3:
			a.ActionID = string(f.bytes)
		case 4:
			a.ProviderID = string(f.bytes)
		case 5:
			if f.wireType == 2 {
				alg, err := ParseAlgorithm(f.bytes)
				if err == nil {
					a.Algorithm = alg
				}
			}
		case 6:
			a.Data = f.bytes
		}
	}
	return a, nil
}

// ParseKeyStorageAction parses crypto/keyStorage/* actions.
func ParseKeyStorageAction(data []byte) (*ParsedKeyStorageAction, error) {
	fields, err := pbParseAll(data)
	if err != nil {
		return nil, err
	}
	a := &ParsedKeyStorageAction{}
	for _, f := range fields {
		switch f.fieldNum {
		case 1:
			a.Version = uint32(f.varint)
		case 2:
			a.Action = string(f.bytes)
		case 3:
			a.ActionID = string(f.bytes)
		case 4:
			a.ProviderID = string(f.bytes)
		case 5:
			// For getItem/removeItem: key (string)
			// For setItem: item (CryptoKeyProto)
			if f.wireType == 2 {
				// Try to determine if this is a key string or a CryptoKeyProto
				// based on the action, but since we parse generically, store both
				a.Key = string(f.bytes)
				// Also try parsing as CryptoKeyProto
				key, err := ParseCryptoKey(f.bytes)
				if err == nil && key.ProviderID != "" {
					a.Item = key
					a.Key = "" // it was a proto, not a string
				}
			}
		case 6:
			if f.wireType == 2 {
				alg, err := ParseAlgorithm(f.bytes)
				if err == nil {
					a.Algorithm = alg
				}
			}
		case 7:
			a.Extractable = f.varint != 0
		case 8:
			a.KeyUsages = append(a.KeyUsages, string(f.bytes))
		}
	}
	return a, nil
}

// ─── CryptoProvider Interface ────────────────────────────────────────────────

// CryptoProvider is the interface that the host application implements to handle
// WebCrypto operations from browser clients.
//
// Each method corresponds to a WebCrypto API call. The server's OnAction
// callback dispatches to these methods after parsing the action proto.
type CryptoProvider interface {
	// GetCrypto selects a crypto provider by ID. Returns provider info.
	// Maps to: provider/action/getCrypto
	GetCrypto(providerID string) ([]byte, error)

	// Sign performs a signing operation.
	// Maps to: crypto/subtle/sign
	Sign(providerID string, algorithm *ParsedAlgorithm, key *ParsedCryptoKey, data []byte) ([]byte, error)

	// Verify verifies a signature.
	// Maps to: crypto/subtle/verify
	Verify(providerID string, algorithm *ParsedAlgorithm, key *ParsedCryptoKey, data, signature []byte) (bool, error)

	// Encrypt encrypts data.
	// Maps to: crypto/subtle/encrypt
	Encrypt(providerID string, algorithm *ParsedAlgorithm, key *ParsedCryptoKey, data []byte) ([]byte, error)

	// Decrypt decrypts data.
	// Maps to: crypto/subtle/decrypt
	Decrypt(providerID string, algorithm *ParsedAlgorithm, key *ParsedCryptoKey, data []byte) ([]byte, error)

	// Digest computes a hash digest.
	// Maps to: crypto/subtle/digest
	Digest(providerID string, algorithm *ParsedAlgorithm, data []byte) ([]byte, error)

	// GenerateKey generates a key or key pair.
	// Maps to: crypto/subtle/generateKey
	// Returns encoded CryptoKeyProto or CryptoKeyPairProto.
	GenerateKey(providerID string, algorithm *ParsedAlgorithm, extractable bool, usages []string) ([]byte, error)

	// ExportKey exports a key.
	// Maps to: crypto/subtle/exportKey
	ExportKey(providerID string, format string, key *ParsedCryptoKey) ([]byte, error)

	// ImportKey imports a key.
	// Maps to: crypto/subtle/importKey
	// Returns encoded CryptoKeyProto.
	ImportKey(providerID string, format string, keyData []byte, algorithm *ParsedAlgorithm, extractable bool, usages []string) ([]byte, error)

	// KeyStorageKeys lists all key IDs.
	// Maps to: crypto/keyStorage/keys
	KeyStorageKeys(providerID string) ([]byte, error)

	// KeyStorageGetItem retrieves a key by ID.
	// Maps to: crypto/keyStorage/getItem
	KeyStorageGetItem(providerID string, keyID string, algorithm *ParsedAlgorithm, extractable bool, usages []string) ([]byte, error)

	// KeyStorageSetItem stores a key.
	// Maps to: crypto/keyStorage/setItem
	KeyStorageSetItem(providerID string, key *ParsedCryptoKey) ([]byte, error)

	// KeyStorageRemoveItem removes a key by ID.
	// Maps to: crypto/keyStorage/removeItem
	KeyStorageRemoveItem(providerID string, keyID string) error

	// KeyStorageIndexOf finds a key by value.
	// Maps to: crypto/keyStorage/indexOf
	KeyStorageIndexOf(providerID string, key *ParsedCryptoKey) ([]byte, error)

	// CertStorageKeys lists all certificate IDs.
	// Maps to: crypto/certificateStorage/keys
	CertStorageKeys(providerID string) ([]byte, error)

	// CertStorageGetItem retrieves a certificate by ID.
	// Maps to: crypto/certificateStorage/getItem
	CertStorageGetItem(providerID string, certID string, algorithm *ParsedAlgorithm, usages []string) ([]byte, error)

	// CertStorageSetItem stores a certificate.
	// Maps to: crypto/certificateStorage/setItem
	CertStorageSetItem(providerID string, data []byte) ([]byte, error)

	// CertStorageRemoveItem removes a certificate by ID.
	// Maps to: crypto/certificateStorage/removeItem
	CertStorageRemoveItem(providerID string, certID string) error

	// CertStorageImport imports a certificate from raw data.
	// Maps to: crypto/certificateStorage/import
	CertStorageImport(providerID string, format string, data []byte, algorithm *ParsedAlgorithm, usages []string) ([]byte, error)

	// CertStorageExport exports a certificate.
	// Maps to: crypto/certificateStorage/export
	CertStorageExport(providerID string, format string, item []byte) ([]byte, error)

	// CertStorageIndexOf finds a certificate.
	// Maps to: crypto/certificateStorage/indexOf
	CertStorageIndexOf(providerID string, item []byte) ([]byte, error)

	// CertStorageGetChain retrieves a certificate chain.
	// Maps to: crypto/certificateStorage/getChain
	CertStorageGetChain(providerID string, item []byte) ([]byte, error)

	// CryptoLogin logs into a crypto token (PKCS#11 PIN entry).
	// Maps to: crypto/login
	CryptoLogin(providerID string) error

	// CryptoLogout logs out of a crypto token.
	// Maps to: crypto/logout
	CryptoLogout(providerID string) error

	// CryptoIsLoggedIn checks token login state.
	// Maps to: crypto/isLoggedIn
	CryptoIsLoggedIn(providerID string) (bool, error)

	// CryptoReset resets the crypto provider state.
	// Maps to: crypto/reset
	CryptoReset(providerID string) error

	// DeriveBits derives bits from a key.
	// Maps to: crypto/subtle/deriveBits
	DeriveBits(providerID string, algorithm *ParsedAlgorithm, key *ParsedCryptoKey, length int) ([]byte, error)

	// DeriveKey derives a new key from a base key.
	// Maps to: crypto/subtle/deriveKey
	DeriveKey(providerID string, algorithm *ParsedAlgorithm, key *ParsedCryptoKey, derivedKeyType *ParsedAlgorithm, extractable bool, usages []string) ([]byte, error)

	// WrapKey wraps (exports + encrypts) a key.
	// Maps to: crypto/subtle/wrapKey
	WrapKey(providerID string, format string, key *ParsedCryptoKey, wrappingKey *ParsedCryptoKey, wrapAlgorithm *ParsedAlgorithm) ([]byte, error)

	// UnwrapKey unwraps (decrypts + imports) a key.
	// Maps to: crypto/subtle/unwrapKey
	UnwrapKey(providerID string, format string, wrappedKey []byte, unwrappingKey *ParsedCryptoKey, unwrapAlgorithm *ParsedAlgorithm, unwrappedKeyAlgorithm *ParsedAlgorithm, extractable bool, usages []string) ([]byte, error)

	// CertStorageGetValue retrieves raw certificate data by ID.
	// Maps to: crypto/certificateStorage/getValue
	CertStorageGetValue(providerID string, certID string) ([]byte, error)

	// CertStorageGetCRL retrieves a CRL from a URL.
	// Maps to: crypto/certificateStorage/getCRL
	CertStorageGetCRL(providerID string, url string) ([]byte, error)

	// CertStorageGetOCSP retrieves an OCSP response.
	// Maps to: crypto/certificateStorage/getOCSP
	CertStorageGetOCSP(providerID string, url string, request []byte) ([]byte, error)
}

// ─── Action Dispatcher ───────────────────────────────────────────────────────

// DispatchAction routes a decrypted action to the appropriate CryptoProvider method.
// This is intended to be used as the OnAction callback in ServerConfig.
func DispatchAction(provider CryptoProvider, action string, payload []byte) ([]byte, error) {
	switch action {
	case "provider/action/getCrypto":
		a, err := ParseAction(payload)
		if err != nil {
			return nil, err
		}
		return provider.GetCrypto(a.ProviderID)

	case "crypto/subtle/sign":
		a, err := ParseSignAction(payload)
		if err != nil {
			return nil, err
		}
		return provider.Sign(a.ProviderID, a.Algorithm, a.Key, a.Data)

	case "crypto/subtle/verify":
		a, err := ParseVerifyAction(payload)
		if err != nil {
			return nil, err
		}
		ok, err := provider.Verify(a.ProviderID, a.Algorithm, a.Key, a.Data, a.Signature)
		if err != nil {
			return nil, err
		}
		if ok {
			return []byte{1}, nil
		}
		return []byte{0}, nil

	case "crypto/subtle/encrypt":
		a, err := ParseSignAction(payload)
		if err != nil {
			return nil, err
		}
		return provider.Encrypt(a.ProviderID, a.Algorithm, a.Key, a.Data)

	case "crypto/subtle/decrypt":
		a, err := ParseSignAction(payload)
		if err != nil {
			return nil, err
		}
		return provider.Decrypt(a.ProviderID, a.Algorithm, a.Key, a.Data)

	case "crypto/subtle/digest":
		a, err := ParseDigestAction(payload)
		if err != nil {
			return nil, err
		}
		return provider.Digest(a.ProviderID, a.Algorithm, a.Data)

	case "crypto/subtle/generateKey":
		a, err := ParseGenerateKeyAction(payload)
		if err != nil {
			return nil, err
		}
		return provider.GenerateKey(a.ProviderID, a.Algorithm, a.Extractable, a.Usages)

	case "crypto/subtle/exportKey":
		a, err := ParseExportKeyAction(payload)
		if err != nil {
			return nil, err
		}
		return provider.ExportKey(a.ProviderID, a.Format, a.Key)

	case "crypto/subtle/importKey":
		fields, err := pbParseAll(payload)
		if err != nil {
			return nil, err
		}
		a := &ParsedImportKeyAction{}
		for _, f := range fields {
			switch f.fieldNum {
			case 4:
				a.ProviderID = string(f.bytes)
			case 5:
				a.Format = string(f.bytes)
			case 6:
				a.KeyData = f.bytes
			case 7:
				if f.wireType == 2 {
					alg, _ := ParseAlgorithm(f.bytes)
					a.Algorithm = alg
				}
			case 8:
				a.Extractable = f.varint != 0
			case 9:
				a.KeyUsages = append(a.KeyUsages, string(f.bytes))
			}
		}
		return provider.ImportKey(a.ProviderID, a.Format, a.KeyData, a.Algorithm, a.Extractable, a.KeyUsages)

	case "crypto/keyStorage/keys":
		a, err := ParseAction(payload)
		if err != nil {
			return nil, err
		}
		return provider.KeyStorageKeys(a.ProviderID)

	case "crypto/keyStorage/getItem":
		// Field 4 = key label (string), field 5 = algorithm, field 6 = extractable, field 7 = usages
		fields, err := pbParseAll(payload)
		if err != nil {
			return nil, err
		}
		var providerID, keyLabel string
		var algorithm *ParsedAlgorithm
		var extractable bool
		var usages []string
		for _, f := range fields {
			switch f.fieldNum {
			case 4:
				providerID = string(f.bytes)
			case 5:
				keyLabel = string(f.bytes)
			case 6:
				if f.wireType == 2 {
					algorithm, _ = ParseAlgorithm(f.bytes)
				}
			case 7:
				extractable = f.varint != 0
			case 8:
				usages = append(usages, string(f.bytes))
			}
		}
		return provider.KeyStorageGetItem(providerID, keyLabel, algorithm, extractable, usages)

	case "crypto/keyStorage/setItem":
		// Field 4 = item (CryptoKeyProto)
		fields, err := pbParseAll(payload)
		if err != nil {
			return nil, err
		}
		var providerID string
		var item *ParsedCryptoKey
		for _, f := range fields {
			switch f.fieldNum {
			case 4:
				providerID = string(f.bytes)
			case 5:
				if f.wireType == 2 {
					item, _ = ParseCryptoKey(f.bytes)
				}
			}
		}
		return provider.KeyStorageSetItem(providerID, item)

	case "crypto/keyStorage/removeItem":
		// Field 4 = key label (string)
		fields, err := pbParseAll(payload)
		if err != nil {
			return nil, err
		}
		var providerID, keyLabel string
		for _, f := range fields {
			switch f.fieldNum {
			case 4:
				providerID = string(f.bytes)
			case 5:
				keyLabel = string(f.bytes)
			}
		}
		err = provider.KeyStorageRemoveItem(providerID, keyLabel)
		return nil, err

	case "crypto/keyStorage/indexOf":
		// Field 4 = item (CryptoKeyProto)
		fields, err := pbParseAll(payload)
		if err != nil {
			return nil, err
		}
		var providerID string
		var item *ParsedCryptoKey
		for _, f := range fields {
			switch f.fieldNum {
			case 4:
				providerID = string(f.bytes)
			case 5:
				if f.wireType == 2 {
					item, _ = ParseCryptoKey(f.bytes)
				}
			}
		}
		return provider.KeyStorageIndexOf(providerID, item)

	case "crypto/keyStorage/clear":
		// Not commonly used, stub
		return nil, nil

	case "crypto/certificateStorage/keys":
		a, err := ParseAction(payload)
		if err != nil {
			return nil, err
		}
		return provider.CertStorageKeys(a.ProviderID)

	case "crypto/certificateStorage/getItem":
		// Field 4 = key label (string), field 5 = algorithm, field 6 = usages
		fields, err := pbParseAll(payload)
		if err != nil {
			return nil, err
		}
		var providerID, keyLabel string
		var algorithm *ParsedAlgorithm
		var usages []string
		for _, f := range fields {
			switch f.fieldNum {
			case 4:
				providerID = string(f.bytes)
			case 5:
				keyLabel = string(f.bytes)
			case 6:
				if f.wireType == 2 {
					algorithm, _ = ParseAlgorithm(f.bytes)
				}
			case 7:
				usages = append(usages, string(f.bytes))
			}
		}
		return provider.CertStorageGetItem(providerID, keyLabel, algorithm, usages)

	case "crypto/certificateStorage/setItem":
		a, err := ParseAction(payload)
		if err != nil {
			return nil, err
		}
		return provider.CertStorageSetItem(a.ProviderID, nil)

	case "crypto/certificateStorage/removeItem":
		// Field 4 = key label (string)
		fields, err := pbParseAll(payload)
		if err != nil {
			return nil, err
		}
		var providerID, keyLabel string
		for _, f := range fields {
			switch f.fieldNum {
			case 4:
				providerID = string(f.bytes)
			case 5:
				keyLabel = string(f.bytes)
			}
		}
		err = provider.CertStorageRemoveItem(providerID, keyLabel)
		return nil, err

	case "crypto/certificateStorage/import":
		fields, err := pbParseAll(payload)
		if err != nil {
			return nil, err
		}
		var providerID, format string
		var data []byte
		var algorithm *ParsedAlgorithm
		var usages []string
		for _, f := range fields {
			switch f.fieldNum {
			case 4:
				providerID = string(f.bytes)
			case 5:
				format = string(f.bytes)
			case 6:
				data = f.bytes
			case 7:
				if f.wireType == 2 {
					alg, _ := ParseAlgorithm(f.bytes)
					algorithm = alg
				}
			case 8:
				usages = append(usages, string(f.bytes))
			}
		}
		return provider.CertStorageImport(providerID, format, data, algorithm, usages)

	case "crypto/certificateStorage/export":
		a, err := ParseExportKeyAction(payload) // similar layout
		if err != nil {
			return nil, err
		}
		return provider.CertStorageExport(a.ProviderID, a.Format, nil)

	case "crypto/certificateStorage/indexOf":
		a, err := ParseKeyStorageAction(payload)
		if err != nil {
			return nil, err
		}
		if a.Item != nil {
			return provider.CertStorageIndexOf(a.ProviderID, nil)
		}
		return nil, nil

	case "crypto/certificateStorage/getChain":
		a, err := ParseKeyStorageAction(payload)
		if err != nil {
			return nil, err
		}
		if a.Item != nil {
			return provider.CertStorageGetChain(a.ProviderID, nil)
		}
		return nil, nil

	case "crypto/certificateStorage/clear":
		return nil, nil

	case "crypto/login":
		a, err := ParseAction(payload)
		if err != nil {
			return nil, err
		}
		err = provider.CryptoLogin(a.ProviderID)
		return nil, err

	case "crypto/logout":
		a, err := ParseAction(payload)
		if err != nil {
			return nil, err
		}
		err = provider.CryptoLogout(a.ProviderID)
		return nil, err

	case "crypto/isLoggedIn":
		a, err := ParseAction(payload)
		if err != nil {
			return nil, err
		}
		loggedIn, err := provider.CryptoIsLoggedIn(a.ProviderID)
		if err != nil {
			return nil, err
		}
		if loggedIn {
			return []byte{1}, nil
		}
		return []byte{0}, nil

	case "crypto/reset":
		a, err := ParseAction(payload)
		if err != nil {
			return nil, err
		}
		err = provider.CryptoReset(a.ProviderID)
		return nil, err

	case "crypto/subtle/deriveBits":
		a, err := ParseSignAction(payload) // algorithm=4, key=5, data=6(length as bytes)
		if err != nil {
			return nil, err
		}
		// length is in field 6 as a uint32, but ParseSignAction reads it as bytes
		// Re-parse to get the varint
		fields, _ := pbParseAll(payload)
		length := 0
		for _, f := range fields {
			if f.fieldNum == 6 && f.wireType == 0 {
				length = int(f.varint)
			}
		}
		return provider.DeriveBits(a.ProviderID, a.Algorithm, a.Key, length)

	case "crypto/subtle/deriveKey":
		fields, err := pbParseAll(payload)
		if err != nil {
			return nil, err
		}
		var providerID string
		var algorithm, derivedKeyType *ParsedAlgorithm
		var key *ParsedCryptoKey
		var extractable bool
		var usages []string
		for _, f := range fields {
			switch f.fieldNum {
			case 4:
				providerID = string(f.bytes)
			case 5:
				if f.wireType == 2 {
					algorithm, _ = ParseAlgorithm(f.bytes)
				}
			case 6:
				if f.wireType == 2 {
					key, _ = ParseCryptoKey(f.bytes)
				}
			case 7:
				if f.wireType == 2 {
					derivedKeyType, _ = ParseAlgorithm(f.bytes)
				}
			case 8:
				extractable = f.varint != 0
			case 9:
				usages = append(usages, string(f.bytes))
			}
		}
		return provider.DeriveKey(providerID, algorithm, key, derivedKeyType, extractable, usages)

	case "crypto/subtle/wrapKey":
		fields, err := pbParseAll(payload)
		if err != nil {
			return nil, err
		}
		var providerID, format string
		var key, wrappingKey *ParsedCryptoKey
		var wrapAlgorithm *ParsedAlgorithm
		for _, f := range fields {
			switch f.fieldNum {
			case 4:
				providerID = string(f.bytes)
			case 5:
				format = string(f.bytes)
			case 6:
				if f.wireType == 2 {
					key, _ = ParseCryptoKey(f.bytes)
				}
			case 7:
				if f.wireType == 2 {
					wrappingKey, _ = ParseCryptoKey(f.bytes)
				}
			case 8:
				if f.wireType == 2 {
					wrapAlgorithm, _ = ParseAlgorithm(f.bytes)
				}
			}
		}
		return provider.WrapKey(providerID, format, key, wrappingKey, wrapAlgorithm)

	case "crypto/subtle/unwrapKey":
		fields, err := pbParseAll(payload)
		if err != nil {
			return nil, err
		}
		var providerID, format string
		var wrappedKey []byte
		var unwrappingKey *ParsedCryptoKey
		var unwrapAlgorithm, unwrappedKeyAlgorithm *ParsedAlgorithm
		var extractable bool
		var usages []string
		for _, f := range fields {
			switch f.fieldNum {
			case 4:
				providerID = string(f.bytes)
			case 5:
				format = string(f.bytes)
			case 6:
				wrappedKey = f.bytes
			case 7:
				if f.wireType == 2 {
					unwrappingKey, _ = ParseCryptoKey(f.bytes)
				}
			case 8:
				if f.wireType == 2 {
					unwrapAlgorithm, _ = ParseAlgorithm(f.bytes)
				}
			case 9:
				if f.wireType == 2 {
					unwrappedKeyAlgorithm, _ = ParseAlgorithm(f.bytes)
				}
			case 10:
				extractable = f.varint != 0
			case 11:
				usages = append(usages, string(f.bytes))
			}
		}
		return provider.UnwrapKey(providerID, format, wrappedKey, unwrappingKey, unwrapAlgorithm, unwrappedKeyAlgorithm, extractable, usages)

	case "crypto/certificateStorage/getValue":
		a, err := ParseKeyStorageAction(payload)
		if err != nil {
			return nil, err
		}
		return provider.CertStorageGetValue(a.ProviderID, a.Key)

	case "crypto/certificateStorage/getCRL":
		fields, err := pbParseAll(payload)
		if err != nil {
			return nil, err
		}
		var providerID, url string
		for _, f := range fields {
			switch f.fieldNum {
			case 4:
				providerID = string(f.bytes)
			case 5:
				url = string(f.bytes)
			}
		}
		return provider.CertStorageGetCRL(providerID, url)

	case "crypto/certificateStorage/getOCSP":
		fields, err := pbParseAll(payload)
		if err != nil {
			return nil, err
		}
		var providerID, url string
		var request []byte
		for _, f := range fields {
			switch f.fieldNum {
			case 4:
				providerID = string(f.bytes)
			case 5:
				url = string(f.bytes)
			case 6:
				request = f.bytes
			}
		}
		return provider.CertStorageGetOCSP(providerID, url, request)

	default:
		return nil, fmt.Errorf("unhandled action: %s", action)
	}
}
