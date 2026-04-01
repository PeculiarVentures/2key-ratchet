package ratchet

import (
	"encoding/hex"
	"strings"
	"testing"
)

// TestDispatchSignFlow tests the full dispatch path for signing:
// build action proto → DispatchAction → parse → adapter → mock client
func TestDispatchSignFlow(t *testing.T) {
	adapter := newStubProvider()

	// Step 1: Get keys via dispatch
	keysPayload := buildActionProto("crypto/keyStorage/keys", "a1", "default")
	keysResult, err := DispatchAction(adapter, "crypto/keyStorage/keys", keysPayload)
	if err != nil {
		t.Fatalf("keyStorage/keys: %v", err)
	}
	keysCSV := string(keysResult)
	t.Logf("keys: %q", keysCSV)
	if !strings.Contains(keysCSV, "private-") {
		t.Fatalf("keys result missing private- prefix: %q", keysCSV)
	}

	// Step 2: Get first private key via dispatch
	var privLabel string
	for _, l := range strings.Split(keysCSV, ",") {
		if strings.HasPrefix(l, "private-") {
			privLabel = l
			break
		}
	}

	getItemPayload := buildKeyStorageGetItemProto("a2", "default", privLabel)
	keyProtoBytes, err := DispatchAction(adapter, "crypto/keyStorage/getItem", getItemPayload)
	if err != nil {
		t.Fatalf("keyStorage/getItem: %v", err)
	}
	t.Logf("key proto: %d bytes", len(keyProtoBytes))

	// Parse the key proto to get the memory ID
	key, err := ParseCryptoKey(keyProtoBytes)
	if err != nil {
		t.Fatalf("ParseCryptoKey: %v", err)
	}
	t.Logf("key: provider=%s type=%s id=%s", key.ProviderID, key.Type, hex.EncodeToString(key.ID))

	// Step 3: Sign via dispatch
	signPayload := buildSignActionProto("a3", "default", "RSASSA-PKCS1-v1_5", "SHA-256", keyProtoBytes, []byte("hello"))
	sig, err := DispatchAction(adapter, "crypto/subtle/sign", signPayload)
	if err != nil {
		t.Fatalf("subtle/sign: %v", err)
	}
	t.Logf("signature: %s", hex.EncodeToString(sig))
	if len(sig) == 0 {
		t.Fatal("empty signature")
	}
}

// TestDispatchExportKey tests exportKey dispatch.
func TestDispatchExportKey(t *testing.T) {
	adapter := newStubProvider()

	// Load a key first
	keysPayload := buildActionProto("crypto/keyStorage/keys", "a1", "default")
	keysResult, _ := DispatchAction(adapter, "crypto/keyStorage/keys", keysPayload)
	var privLabel string
	for _, l := range strings.Split(string(keysResult), ",") {
		if strings.HasPrefix(l, "private-") {
			privLabel = l
			break
		}
	}

	getItemPayload := buildKeyStorageGetItemProto("a2", "default", privLabel)
	keyProtoBytes, _ := DispatchAction(adapter, "crypto/keyStorage/getItem", getItemPayload)

	// Export
	exportPayload := buildExportKeyProto("a3", "default", "spki", keyProtoBytes)
	result, err := DispatchAction(adapter, "crypto/subtle/exportKey", exportPayload)
	if err != nil {
		t.Fatalf("exportKey: %v", err)
	}
	t.Logf("exported key: %d bytes", len(result))
	if len(result) == 0 {
		t.Fatal("empty export")
	}
}

// TestDispatchDigest tests digest dispatch.
func TestDispatchDigest(t *testing.T) {
	adapter := newStubProvider()

	digestPayload := buildDigestActionProto("a1", "default", "SHA-256", []byte("hello world"))
	result, err := DispatchAction(adapter, "crypto/subtle/digest", digestPayload)
	if err != nil {
		t.Fatalf("digest: %v", err)
	}
	expected := "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
	if hex.EncodeToString(result) != expected {
		t.Errorf("digest = %s, want %s", hex.EncodeToString(result), expected)
	}
}

// TestDispatchCertStorageKeys tests cert key listing.
func TestDispatchCertStorageKeys(t *testing.T) {
	adapter := newStubProvider()

	payload := buildActionProto("crypto/certificateStorage/keys", "a1", "default")
	result, err := DispatchAction(adapter, "crypto/certificateStorage/keys", payload)
	if err != nil {
		t.Fatalf("certStorage/keys: %v", err)
	}
	csv := string(result)
	t.Logf("cert keys: %q", csv)
	if !strings.Contains(csv, "x509-") {
		t.Errorf("cert keys missing x509- prefix: %q", csv)
	}
}

// TestDispatchCertStorageGetItem tests cert retrieval with metadata.
func TestDispatchCertStorageGetItem(t *testing.T) {
	adapter := newStubProvider()

	// Get cert labels
	payload := buildActionProto("crypto/certificateStorage/keys", "a1", "default")
	result, _ := DispatchAction(adapter, "crypto/certificateStorage/keys", payload)
	certLabel := strings.Split(string(result), ",")[0]

	// Get cert item
	getPayload := buildKeyStorageGetItemProto("a2", "default", certLabel)
	certProto, err := DispatchAction(adapter, "crypto/certificateStorage/getItem", getPayload)
	if err != nil {
		t.Fatalf("certStorage/getItem: %v", err)
	}

	// Parse to verify field IDs
	fields, _ := pbParseAll(certProto)
	fieldNums := make(map[int]bool)
	for _, f := range fields {
		fieldNums[f.fieldNum] = true
	}

	// Must have: 1(providerID), 2(id), 5(publicKey), 11(issuer), 12(subject), 13(notBefore), 14(notAfter)
	required := []int{1, 2, 5, 11, 12, 13, 14}
	for _, fid := range required {
		if !fieldNums[fid] {
			t.Errorf("missing field %d in cert proto", fid)
		}
	}
	t.Logf("cert proto: %d bytes, %d fields", len(certProto), len(fields))
}

// TestDispatchGetCrypto tests provider selection.
func TestDispatchGetCrypto(t *testing.T) {
	adapter := newStubProvider()

	payload := buildGetCryptoProto("a1", "default")
	result, err := DispatchAction(adapter, "provider/action/getCrypto", payload)
	if err != nil {
		t.Fatalf("getCrypto: %v", err)
	}
	if len(result) == 0 {
		t.Fatal("empty getCrypto response")
	}
}

// TestDispatchCryptoLogin tests crypto login/logout/isLoggedIn.
func TestDispatchCryptoLogin(t *testing.T) {
	adapter := newStubProvider()

	payload := buildActionProto("crypto/isLoggedIn", "a1", "default")
	result, err := DispatchAction(adapter, "crypto/isLoggedIn", payload)
	if err != nil {
		t.Fatalf("isLoggedIn: %v", err)
	}
	if len(result) != 1 || result[0] != 1 {
		t.Errorf("isLoggedIn = %v, want [1]", result)
	}

	payload = buildActionProto("crypto/login", "a2", "default")
	_, err = DispatchAction(adapter, "crypto/login", payload)
	if err != nil {
		t.Fatalf("login: %v", err)
	}

	payload = buildActionProto("crypto/logout", "a3", "default")
	_, err = DispatchAction(adapter, "crypto/logout", payload)
	if err != nil {
		t.Fatalf("logout: %v", err)
	}
}

// TestDispatchIndexOfRoundTrip tests the indexOf → getItem round-trip through dispatch.
func TestDispatchIndexOfRoundTrip(t *testing.T) {
	adapter := newStubProvider()

	// Get keys
	keysResult, _ := DispatchAction(adapter, "crypto/keyStorage/keys",
		buildActionProto("crypto/keyStorage/keys", "a1", "default"))
	var privLabel string
	for _, l := range strings.Split(string(keysResult), ",") {
		if strings.HasPrefix(l, "private-") {
			privLabel = l
			break
		}
	}

	// getItem
	keyProto, _ := DispatchAction(adapter, "crypto/keyStorage/getItem",
		buildKeyStorageGetItemProto("a2", "default", privLabel))

	// indexOf — sends the CryptoKeyProto as field 4
	indexOfPayload := buildIndexOfProto("a3", "default", keyProto)
	result, err := DispatchAction(adapter, "crypto/keyStorage/indexOf", indexOfPayload)
	if err != nil {
		t.Fatalf("indexOf: %v", err)
	}
	label := string(result)
	t.Logf("indexOf returned: %q", label)
	if !strings.HasPrefix(label, "private-") {
		t.Errorf("indexOf result %q should start with private-", label)
	}

	// getItem again with the indexOf result
	keyProto2, err := DispatchAction(adapter, "crypto/keyStorage/getItem",
		buildKeyStorageGetItemProto("a4", "default", label))
	if err != nil {
		t.Fatalf("getItem(indexOf result): %v", err)
	}
	if len(keyProto2) == 0 {
		t.Fatal("empty getItem result from indexOf label")
	}
	t.Log("indexOf → getItem round-trip through dispatch: OK")
}

// TestDispatchUnsupportedActions verifies unsupported actions return errors, not panics.
func TestDispatchUnsupportedActions(t *testing.T) {
	adapter := newStubProvider()

	unsupported := []string{
		"crypto/subtle/generateKey",
		"crypto/subtle/importKey",
		"crypto/subtle/deriveBits",
		"crypto/subtle/deriveKey",
		"crypto/subtle/wrapKey",
		"crypto/subtle/unwrapKey",
	}

	for _, action := range unsupported {
		payload := buildActionProto(action, "a1", "default")
		_, err := DispatchAction(adapter, action, payload)
		if err == nil {
			t.Errorf("%s should return error", action)
		} else {
			t.Logf("%s: %v (expected)", action, err)
		}
	}
}

// ─── Proto builders ──────────────────────────────────────────────────────────

// buildActionProto builds a minimal ActionProto with CryptoActionProto providerID.
func buildActionProto(action, actionID, providerID string) []byte {
	var buf []byte
	buf = append(buf, pbUint32Field(1, 1)...)
	buf = append(buf, pbBytesField(2, []byte(action))...)
	buf = append(buf, pbBytesField(3, []byte(actionID))...)
	buf = append(buf, pbBytesField(4, []byte(providerID))...)
	return buf
}

// buildKeyStorageGetItemProto builds a KeyStorageGetItemActionProto.
// Field 4 = key label (string).
func buildKeyStorageGetItemProto(actionID, providerID, keyLabel string) []byte {
	var buf []byte
	buf = append(buf, pbUint32Field(1, 1)...)
	buf = append(buf, pbBytesField(2, []byte("crypto/keyStorage/getItem"))...)
	buf = append(buf, pbBytesField(3, []byte(actionID))...)
	buf = append(buf, pbBytesField(4, []byte(providerID))...)
	buf = append(buf, pbBytesField(5, []byte(keyLabel))...)
	return buf
}

// buildSignActionProto builds a SignActionProto.
// Field 4 = algorithm (nested), field 5 = key (nested CryptoKeyProto), field 6 = data.
func buildSignActionProto(actionID, providerID, algName, hashName string, keyProto, data []byte) []byte {
	// Build AlgorithmProto
	var hashBuf []byte
	hashBuf = append(hashBuf, pbUint32Field(1, 1)...)
	hashBuf = append(hashBuf, pbBytesField(2, []byte(hashName))...)

	var algBuf []byte
	algBuf = append(algBuf, pbUint32Field(1, 1)...)
	algBuf = append(algBuf, pbBytesField(2, []byte(algName))...)
	algBuf = append(algBuf, pbBytesField(3, hashBuf)...)

	var buf []byte
	buf = append(buf, pbUint32Field(1, 1)...)
	buf = append(buf, pbBytesField(2, []byte("crypto/subtle/sign"))...)
	buf = append(buf, pbBytesField(3, []byte(actionID))...)
	buf = append(buf, pbBytesField(4, []byte(providerID))...)
	buf = append(buf, pbBytesField(5, algBuf)...)
	buf = append(buf, pbBytesField(6, keyProto)...)
	buf = append(buf, pbBytesField(7, data)...)
	return buf
}

// buildExportKeyProto builds an ExportKeyActionProto.
func buildExportKeyProto(actionID, providerID, format string, keyProto []byte) []byte {
	var buf []byte
	buf = append(buf, pbUint32Field(1, 1)...)
	buf = append(buf, pbBytesField(2, []byte("crypto/subtle/exportKey"))...)
	buf = append(buf, pbBytesField(3, []byte(actionID))...)
	buf = append(buf, pbBytesField(4, []byte(providerID))...)
	buf = append(buf, pbBytesField(5, []byte(format))...)
	buf = append(buf, pbBytesField(6, keyProto)...)
	return buf
}

// buildDigestActionProto builds a DigestActionProto.
func buildDigestActionProto(actionID, providerID, algName string, data []byte) []byte {
	var algBuf []byte
	algBuf = append(algBuf, pbUint32Field(1, 1)...)
	algBuf = append(algBuf, pbBytesField(2, []byte(algName))...)

	var buf []byte
	buf = append(buf, pbUint32Field(1, 1)...)
	buf = append(buf, pbBytesField(2, []byte("crypto/subtle/digest"))...)
	buf = append(buf, pbBytesField(3, []byte(actionID))...)
	buf = append(buf, pbBytesField(4, []byte(providerID))...)
	buf = append(buf, pbBytesField(5, algBuf)...)
	buf = append(buf, pbBytesField(6, data)...)
	return buf
}

// buildGetCryptoProto builds a ProviderGetCryptoActionProto.
func buildGetCryptoProto(actionID, cryptoID string) []byte {
	var buf []byte
	buf = append(buf, pbUint32Field(1, 1)...)
	buf = append(buf, pbBytesField(2, []byte("provider/action/getCrypto"))...)
	buf = append(buf, pbBytesField(3, []byte(actionID))...)
	buf = append(buf, pbBytesField(4, []byte(cryptoID))...)
	return buf
}

// buildIndexOfProto builds a KeyStorageIndexOfActionProto.
// Field 4 = item (CryptoKeyProto).
func buildIndexOfProto(actionID, providerID string, keyProto []byte) []byte {
	var buf []byte
	buf = append(buf, pbUint32Field(1, 1)...)
	buf = append(buf, pbBytesField(2, []byte("crypto/keyStorage/indexOf"))...)
	buf = append(buf, pbBytesField(3, []byte(actionID))...)
	buf = append(buf, pbBytesField(4, []byte(providerID))...)
	buf = append(buf, pbBytesField(5, keyProto)...)
	return buf
}
