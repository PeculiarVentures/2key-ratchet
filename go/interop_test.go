package ratchet

import (
	"crypto/ecdh"
	"crypto/elliptic"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// vectorsFile finds vectors.json relative to the test file location.
func vectorsFile() string {
	_, thisFile, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(thisFile), "..", "interop", "vectors.json")
}

type ecJWK struct {
	D string `json:"d"`
	X string `json:"x"`
	Y string `json:"y"`
}

type testVectors struct {
	Bob struct {
		SigningPub       string `json:"signingPub"`
		ExchangePub      string `json:"exchangePub"`
		ExchangePriv     ecJWK  `json:"exchangePriv"`
		SignedPreKeyPub  string `json:"signedPreKeyPub"`
		SignedPreKeyPriv ecJWK  `json:"signedPreKeyPriv"`
		OneTimePreKeyPub string `json:"oneTimePreKeyPub"`
		OneTimePreKeyPriv ecJWK `json:"oneTimePreKeyPriv"`
	} `json:"bob"`
	Alice struct {
		SigningPub   string `json:"signingPub"`
		ExchangePub  string `json:"exchangePub"`
		ExchangePriv ecJWK  `json:"exchangePriv"`
	} `json:"alice"`
	BobSigningThumbprint   string `json:"bobSigningThumbprint"`
	AliceSigningThumbprint string `json:"aliceSigningThumbprint"`
	ChallengePin           string `json:"challengePin"`
	AliceEphemeralPub      string `json:"aliceEphemeralPub"`
	AliceEphemeralPriv     ecJWK  `json:"aliceEphemeralPriv"`
	X3DH struct {
		DH1     string `json:"dh1"`
		DH2     string `json:"dh2"`
		DH3     string `json:"dh3"`
		DH4     string `json:"dh4"`
		KM      string `json:"km"`
		HkdfPRK string `json:"hkdfPRK"`
		RootKey string `json:"rootKey"`
	} `json:"x3dh"`
	ChainKDF struct {
		InputChainKey string `json:"inputChainKey"`
		CipherKey     string `json:"cipherKey"`
		NextChainKey  string `json:"nextChainKey"`
	} `json:"chainKDF"`
	MessageKeys struct {
		HkdfPRK    string `json:"hkdfPRK"`
		AESKey     string `json:"aesKey"`
		HMACKey    string `json:"hmacKey"`
		IVMaterial string `json:"ivMaterial"`
		IV         string `json:"iv"`
	} `json:"messageKeys"`
	AESCBC struct {
		Plaintext  string `json:"plaintext"`
		Ciphertext string `json:"ciphertext"`
	} `json:"aesCBC"`
	Negative struct {
		WrongIdentitySignature string `json:"wrongIdentitySignature"`
		WrongPreKeySignature   string `json:"wrongPreKeySignature"`
		TamperedBundleProto    string `json:"tamperedBundleProto"`
	} `json:"negative"`
}

func loadVectors(t *testing.T) *testVectors {
	t.Helper()
	path := vectorsFile()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Skipf("vectors.json not found at %s (run: cd interop && npm run generate)", path)
	}
	var v testVectors
	if err := json.Unmarshal(data, &v); err != nil {
		t.Fatalf("parse vectors.json: %v", err)
	}
	return &v
}

// jwkToECDHPrivate converts a JWK EC private key to *ecdh.PrivateKey.
func jwkToECDHPrivate(t *testing.T, jwk ecJWK) *ecdh.PrivateKey {
	t.Helper()
	dBytes, err := base64.RawURLEncoding.DecodeString(jwk.D)
	if err != nil {
		t.Fatalf("decode JWK d: %v", err)
	}
	// P-256 private key is the raw scalar (32 bytes)
	if len(dBytes) < 32 {
		padded := make([]byte, 32)
		copy(padded[32-len(dBytes):], dBytes)
		dBytes = padded
	}
	key, err := ecdh.P256().NewPrivateKey(dBytes)
	if err != nil {
		t.Fatalf("parse ECDH private key: %v", err)
	}
	return key
}

// jwkToECDHPublic converts JWK x,y to uncompressed public key bytes.
func jwkToUncompressedPub(t *testing.T, jwk ecJWK) []byte {
	t.Helper()
	xBytes, _ := base64.RawURLEncoding.DecodeString(jwk.X)
	yBytes, _ := base64.RawURLEncoding.DecodeString(jwk.Y)
	x := new(big.Int).SetBytes(xBytes)
	y := new(big.Int).SetBytes(yBytes)
	return elliptic.Marshal(elliptic.P256(), x, y)
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("hex decode: %v", err)
	}
	return b
}

func assertHexEq(t *testing.T, name string, got []byte, wantHex string) {
	t.Helper()
	gotHex := hex.EncodeToString(got)
	if gotHex != wantHex {
		t.Fatalf("%s:\n  got:  %s\n  want: %s", name, gotHex, wantHex)
	}
}

// ─── Interop Tests ───────────────────────────────────────────────────────────

func TestInteropThumbprint(t *testing.T) {
	v := loadVectors(t)

	bobSigPub := mustHex(t, v.Bob.SigningPub)
	aliceSigPub := mustHex(t, v.Alice.SigningPub)

	bobThumb := Thumbprint(bobSigPub)
	if bobThumb != v.BobSigningThumbprint {
		t.Fatalf("bob thumbprint:\n  got:  %s\n  want: %s", bobThumb, v.BobSigningThumbprint)
	}

	aliceThumb := Thumbprint(aliceSigPub)
	if aliceThumb != v.AliceSigningThumbprint {
		t.Fatalf("alice thumbprint:\n  got:  %s\n  want: %s", aliceThumb, v.AliceSigningThumbprint)
	}
}

func TestInteropChallengePin(t *testing.T) {
	v := loadVectors(t)

	bobSigPub := mustHex(t, v.Bob.SigningPub)
	aliceSigPub := mustHex(t, v.Alice.SigningPub)

	pin := ComputeChallenge(bobSigPub, aliceSigPub)
	if pin != v.ChallengePin {
		t.Fatalf("challenge pin:\n  got:  %s\n  want: %s", pin, v.ChallengePin)
	}
}

func TestInteropChainKDF(t *testing.T) {
	v := loadVectors(t)

	ck := mustHex(t, v.ChainKDF.InputChainKey)
	chain := &SymmetricChain{RootKey: ck}

	cipherKey, err := chain.Step()
	if err != nil {
		t.Fatal(err)
	}

	assertHexEq(t, "cipher key", cipherKey, v.ChainKDF.CipherKey)
	assertHexEq(t, "next chain key", chain.RootKey, v.ChainKDF.NextChainKey)
}

func TestInteropMessageKeys(t *testing.T) {
	v := loadVectors(t)

	cipherKey := mustHex(t, v.ChainKDF.CipherKey)
	mk, err := DeriveMessageKeys(cipherKey)
	if err != nil {
		t.Fatal(err)
	}

	assertHexEq(t, "AES key", mk.AESKey, v.MessageKeys.AESKey)
	assertHexEq(t, "HMAC key", mk.HMACKey, v.MessageKeys.HMACKey)
	assertHexEq(t, "IV", mk.IV, v.MessageKeys.IV)
}

func TestInteropAESCBC(t *testing.T) {
	v := loadVectors(t)

	aesKey := mustHex(t, v.MessageKeys.AESKey)
	iv := mustHex(t, v.MessageKeys.IV)

	ct, err := AESCBCEncrypt(aesKey, iv, []byte(v.AESCBC.Plaintext))
	if err != nil {
		t.Fatal(err)
	}
	assertHexEq(t, "ciphertext", ct, v.AESCBC.Ciphertext)

	pt, err := AESCBCDecrypt(aesKey, iv, ct)
	if err != nil {
		t.Fatal(err)
	}
	if string(pt) != v.AESCBC.Plaintext {
		t.Fatalf("decrypt: got %q, want %q", string(pt), v.AESCBC.Plaintext)
	}
}

func TestInteropX3DHDeriveBytes(t *testing.T) {
	v := loadVectors(t)

	// Parse Alice's exchange private key
	aliceExPriv := jwkToECDHPrivate(t, v.Alice.ExchangePriv)

	// Parse Bob's signed pre-key public
	bobSPKPub, err := ecdh.P256().NewPublicKey(mustHex(t, v.Bob.SignedPreKeyPub))
	if err != nil {
		t.Fatal(err)
	}

	// DH1 = DH(alice.exchangeKey, bob.signedPreKeyPub)
	dh1, err := aliceExPriv.ECDH(bobSPKPub)
	if err != nil {
		t.Fatal(err)
	}
	assertHexEq(t, "DH1", dh1, v.X3DH.DH1)

	// Parse Alice's ephemeral key
	aliceEphPriv := jwkToECDHPrivate(t, v.AliceEphemeralPriv)

	// Parse Bob's exchange public
	bobExPub, err := ecdh.P256().NewPublicKey(mustHex(t, v.Bob.ExchangePub))
	if err != nil {
		t.Fatal(err)
	}

	// DH2 = DH(alice.ephemeral, bob.exchangePub)
	dh2, err := aliceEphPriv.ECDH(bobExPub)
	if err != nil {
		t.Fatal(err)
	}
	assertHexEq(t, "DH2", dh2, v.X3DH.DH2)

	// DH3 = DH(alice.ephemeral, bob.signedPreKeyPub)
	dh3, err := aliceEphPriv.ECDH(bobSPKPub)
	if err != nil {
		t.Fatal(err)
	}
	assertHexEq(t, "DH3", dh3, v.X3DH.DH3)

	// Parse Bob's one-time pre-key public
	bobOPKPub, err := ecdh.P256().NewPublicKey(mustHex(t, v.Bob.OneTimePreKeyPub))
	if err != nil {
		t.Fatal(err)
	}

	// DH4 = DH(alice.ephemeral, bob.oneTimePreKeyPub)
	dh4, err := aliceEphPriv.ECDH(bobOPKPub)
	if err != nil {
		t.Fatal(err)
	}
	assertHexEq(t, "DH4", dh4, v.X3DH.DH4)
}

func TestInteropX3DHRootKey(t *testing.T) {
	v := loadVectors(t)

	dh1 := mustHex(t, v.X3DH.DH1)
	dh2 := mustHex(t, v.X3DH.DH2)
	dh3 := mustHex(t, v.X3DH.DH3)
	dh4 := mustHex(t, v.X3DH.DH4)

	rootKey, err := deriveRootKey(dh1, dh2, dh3, dh4)
	if err != nil {
		t.Fatal(err)
	}
	assertHexEq(t, "root key", rootKey, v.X3DH.RootKey)
}

func TestInteropX3DHAuthenticateAB(t *testing.T) {
	v := loadVectors(t)

	// Parse all keys from JWK
	aliceExPriv := jwkToECDHPrivate(t, v.Alice.ExchangePriv)
	aliceEphPriv := jwkToECDHPrivate(t, v.AliceEphemeralPriv)
	bobExPriv := jwkToECDHPrivate(t, v.Bob.ExchangePriv)
	bobSPKPriv := jwkToECDHPrivate(t, v.Bob.SignedPreKeyPriv)
	bobOPKPriv := jwkToECDHPrivate(t, v.Bob.OneTimePreKeyPriv)

	bobExPub, _ := ecdh.P256().NewPublicKey(mustHex(t, v.Bob.ExchangePub))
	bobSPKPub, _ := ecdh.P256().NewPublicKey(mustHex(t, v.Bob.SignedPreKeyPub))
	bobOPKPub, _ := ecdh.P256().NewPublicKey(mustHex(t, v.Bob.OneTimePreKeyPub))
	aliceExPub, _ := ecdh.P256().NewPublicKey(mustHex(t, v.Alice.ExchangePub))
	aliceEphPub, _ := ecdh.P256().NewPublicKey(mustHex(t, v.AliceEphemeralPub))

	// AuthenticateA (Alice side)
	rootKeyA, err := AuthenticateA(aliceExPriv, aliceEphPriv, bobExPub, bobSPKPub, bobOPKPub)
	if err != nil {
		t.Fatalf("AuthenticateA: %v", err)
	}
	assertHexEq(t, "AuthenticateA root key", rootKeyA, v.X3DH.RootKey)

	// AuthenticateB (Bob side)
	rootKeyB, err := AuthenticateB(bobExPriv, bobSPKPriv, aliceExPub, aliceEphPub, bobOPKPriv)
	if err != nil {
		t.Fatalf("AuthenticateB: %v", err)
	}
	assertHexEq(t, "AuthenticateB root key", rootKeyB, v.X3DH.RootKey)

	// Both must match
	if hex.EncodeToString(rootKeyA) != hex.EncodeToString(rootKeyB) {
		t.Fatal("AuthenticateA and AuthenticateB produced different root keys")
	}
}

func TestInteropX3DHWithoutOneTimePreKey(t *testing.T) {
	v := loadVectors(t)

	aliceExPriv := jwkToECDHPrivate(t, v.Alice.ExchangePriv)
	aliceEphPriv := jwkToECDHPrivate(t, v.AliceEphemeralPriv)
	bobExPriv := jwkToECDHPrivate(t, v.Bob.ExchangePriv)
	bobSPKPriv := jwkToECDHPrivate(t, v.Bob.SignedPreKeyPriv)

	bobExPub, _ := ecdh.P256().NewPublicKey(mustHex(t, v.Bob.ExchangePub))
	bobSPKPub, _ := ecdh.P256().NewPublicKey(mustHex(t, v.Bob.SignedPreKeyPub))
	aliceExPub, _ := ecdh.P256().NewPublicKey(mustHex(t, v.Alice.ExchangePub))
	aliceEphPub, _ := ecdh.P256().NewPublicKey(mustHex(t, v.AliceEphemeralPub))

	// Without OPK (nil)
	rootKeyA, err := AuthenticateA(aliceExPriv, aliceEphPriv, bobExPub, bobSPKPub, nil)
	if err != nil {
		t.Fatal(err)
	}
	rootKeyB, err := AuthenticateB(bobExPriv, bobSPKPriv, aliceExPub, aliceEphPub, nil)
	if err != nil {
		t.Fatal(err)
	}

	if hex.EncodeToString(rootKeyA) != hex.EncodeToString(rootKeyB) {
		t.Fatal("root keys don't match without OPK")
	}

	// Root key without OPK should differ from root key with OPK
	if hex.EncodeToString(rootKeyA) == v.X3DH.RootKey {
		t.Fatal("root key with and without OPK should differ")
	}
}

func TestInteropFullSessionRoundTrip(t *testing.T) {
	v := loadVectors(t)

	// Reconstruct both sessions from the vector keys and verify encrypt/decrypt
	aliceExPriv := jwkToECDHPrivate(t, v.Alice.ExchangePriv)
	aliceEphPriv := jwkToECDHPrivate(t, v.AliceEphemeralPriv)
	bobExPriv := jwkToECDHPrivate(t, v.Bob.ExchangePriv)
	bobSPKPriv := jwkToECDHPrivate(t, v.Bob.SignedPreKeyPriv)
	bobOPKPriv := jwkToECDHPrivate(t, v.Bob.OneTimePreKeyPriv)

	bobExPub, _ := ecdh.P256().NewPublicKey(mustHex(t, v.Bob.ExchangePub))
	bobSPKPub, _ := ecdh.P256().NewPublicKey(mustHex(t, v.Bob.SignedPreKeyPub))
	bobOPKPub, _ := ecdh.P256().NewPublicKey(mustHex(t, v.Bob.OneTimePreKeyPub))
	aliceExPub, _ := ecdh.P256().NewPublicKey(mustHex(t, v.Alice.ExchangePub))
	aliceEphPub, _ := ecdh.P256().NewPublicKey(mustHex(t, v.AliceEphemeralPub))

	// Alice session
	rootKeyA, _ := AuthenticateA(aliceExPriv, aliceEphPriv, bobExPub, bobSPKPub, bobOPKPub)
	aliceSess := &Session{
		RootKey:    rootKeyA,
		RatchetKey: aliceEphPriv,
		CurrentStep: &DHRatchetStep{
			RemoteRatchetKey: bobSPKPub,
		},
		SkippedKeys: make(map[string]*skippedKeyEntry), SkippedKeyTTL: DefaultSkippedKeyTTL,
	}

	// Bob session
	rootKeyB, _ := AuthenticateB(bobExPriv, bobSPKPriv, aliceExPub, aliceEphPub, bobOPKPriv)
	bobSess := &Session{
		RootKey:    rootKeyB,
		RatchetKey: bobSPKPriv,
		CurrentStep: &DHRatchetStep{},
		SkippedKeys: make(map[string]*skippedKeyEntry), SkippedKeyTTL: DefaultSkippedKeyTTL,
	}

	// Alice encrypts
	ct, _, counter, err := aliceSess.EncryptMessage([]byte("Hello from Alice"))
	if err != nil {
		t.Fatalf("alice encrypt: %v", err)
	}

	// Bob decrypts
	pt, _, err := bobSess.DecryptMessage(ct, aliceEphPub, counter)
	if err != nil {
		t.Fatalf("bob decrypt: %v", err)
	}
	if string(pt) != "Hello from Alice" {
		t.Fatalf("bob got %q, want %q", string(pt), "Hello from Alice")
	}
	t.Logf("Bob decrypted: %q", string(pt))

	_ = bobOPKPriv
}
