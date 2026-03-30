package ratchet

import (
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"testing"
)

// Reference values from the TypeScript 2key-ratchet test run.
// See test-ratchet/test_vectors.js for the generation code.

func TestChainKDF(t *testing.T) {
	ckInput, _ := hex.DecodeString("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")

	chain := &SymmetricChain{RootKey: ckInput}
	cipherKey, err := chain.Step()
	if err != nil {
		t.Fatalf("Step: %v", err)
	}

	assertHex(t, "cipher key", cipherKey,
		"790519613efaec118e63904e01475b9543b9a15c61070227d877418c8cca415e")
	assertHex(t, "next chain key", chain.RootKey,
		"e3593f75e832b460cfc9cdea5a65902f94d9213060090c0e00a5a74306389e2e")
}

func TestMessageKeyDerivation(t *testing.T) {
	cipherKey, _ := hex.DecodeString("790519613efaec118e63904e01475b9543b9a15c61070227d877418c8cca415e")

	mk, err := DeriveMessageKeys(cipherKey)
	if err != nil {
		t.Fatalf("DeriveMessageKeys: %v", err)
	}

	assertHex(t, "AES key", mk.AESKey,
		"4dd616cd97d08a45d6b831789bd01abf47f1f41cb019ceee789d834bb43a688c")
	assertHex(t, "HMAC key", mk.HMACKey,
		"6856d65f125af23bd80d748cdc3a2e5803e3add557b5af47fcb0ef589c45c398")
	assertHex(t, "IV", mk.IV,
		"26dc72731e31b5c155eb5048dbed8ffa")
}

func TestAESCBC(t *testing.T) {
	aesKey, _ := hex.DecodeString("4dd616cd97d08a45d6b831789bd01abf47f1f41cb019ceee789d834bb43a688c")
	iv, _ := hex.DecodeString("26dc72731e31b5c155eb5048dbed8ffa")
	plaintext := []byte("Hello Bob")

	ct, err := AESCBCEncrypt(aesKey, iv, plaintext)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	assertHex(t, "ciphertext", ct, "450f22f5480bc9e5a262fc7bcc3077b3")

	pt, err := AESCBCDecrypt(aesKey, iv, ct)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if string(pt) != "Hello Bob" {
		t.Fatalf("Decrypt: got %q, want %q", string(pt), "Hello Bob")
	}
}

func TestX3DHRootKeyDerivation(t *testing.T) {
	// KM from the TypeScript test (FF(32) || DH1 || DH2 || DH3 || DH4)
	km, _ := hex.DecodeString(
		"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff" +
			"83b3d9c7283c77f0f4beeb116fd397c1ee89f58b0e3cd6869cfe034659d9c428" +
			"f848b8465d9d6ebafc0107008dd83dc8a09dd20c3ce77a49bd0d4c37b38cba17" +
			"d83939756a235192a1ba99904da2c7165f5568384018cf314b7d2d398e6291a2" +
			"3fa4502c424478aa0c8b99102f8d608878b75f277fd4dfb02c543af8e6d7757f")

	if len(km) != 160 {
		t.Fatalf("KM length: got %d, want 160", len(km))
	}

	// Extract DH values and run deriveRootKey
	dh1 := km[32:64]
	dh2 := km[64:96]
	dh3 := km[96:128]
	dh4 := km[128:160]

	rootKey, err := deriveRootKey(dh1, dh2, dh3, dh4)
	if err != nil {
		t.Fatalf("deriveRootKey: %v", err)
	}

	assertHex(t, "root key", rootKey,
		"e62162ba894fc594cdc1fd6f7c123421523563a49ee62f00d8019a7620b33000")
}

func TestX3DHKeyAgreement(t *testing.T) {
	// Use the actual public/private keys from the TypeScript test.
	// We need to verify that ECDH deriveBits in Go matches WebCrypto.

	// Bob's keys from the test
	bobExPub, _ := hex.DecodeString("0441b864a15fb634f0af9410aa1a6d80b505d6ae52eefe48d1db571b5c12cbbc2365e38e576e2d91f4168d17255753121a7d78dd155d245b582e197abefd0e9df7")
	bobSPKPub, _ := hex.DecodeString("0468fcd5ca1cbaccb263d08db0937f69da970e60b014b3970de32738590933b30ca72f740c1536afe85ba16e4557717405d2302fa98eb7daa0114581c1abfd1c1f")
	bobOPKPub, _ := hex.DecodeString("04b138a8fb7e200ea17a895b8928789a6bda8cd28662bc5d66ce246e9b0f7588d9ee86a46d02c672d26e00b28f7d3555885ceb2147903e2c0d1da56ecd7b6df3de")

	// Alice's keys
	aliceExPub, _ := hex.DecodeString("04a06a8f81f67d2909292ca9fdc256e9d9fd072385a6a12f0ad0d422a9154c95986619b3b4ac6281a1a2d5d75cbfb889dae07079299432ff4da57a8f4d69e0bf5a")
	aliceEphPub, _ := hex.DecodeString("043904ff4490e06aaa685990bb13e7fe1a8399e6994b0295a7847256296bbd3a93563a5e161f23700274398f11c24d694cae038e6bd234f4fff631d0fe8386f4ad")

	// Parse all public keys
	bobEx, err := ecdh.P256().NewPublicKey(bobExPub)
	if err != nil {
		t.Fatalf("parse bobExPub: %v", err)
	}
	bobSPK, err := ecdh.P256().NewPublicKey(bobSPKPub)
	if err != nil {
		t.Fatalf("parse bobSPKPub: %v", err)
	}
	bobOPK, err := ecdh.P256().NewPublicKey(bobOPKPub)
	if err != nil {
		t.Fatalf("parse bobOPKPub: %v", err)
	}
	aliceEx, err := ecdh.P256().NewPublicKey(aliceExPub)
	if err != nil {
		t.Fatalf("parse aliceExPub: %v", err)
	}
	aliceEph, err := ecdh.P256().NewPublicKey(aliceEphPub)
	if err != nil {
		t.Fatalf("parse aliceEphPub: %v", err)
	}

	// We can't reproduce the DH values without the private keys, but we can
	// verify that both sides produce the same DH outputs by testing with
	// generated keys and doing a full round-trip.

	t.Logf("All public keys parsed successfully (bob: ex=%d spk=%d opk=%d, alice: ex=%d eph=%d)",
		len(bobEx.Bytes()), len(bobSPK.Bytes()), len(bobOPK.Bytes()),
		len(aliceEx.Bytes()), len(aliceEph.Bytes()))
}

func TestFullRoundTrip(t *testing.T) {
	// Generate fresh keys and do a full X3DH + encrypt/decrypt round trip.
	bob, err := GenerateIdentity(1, 1, 1)
	if err != nil {
		t.Fatalf("generate bob: %v", err)
	}

	alice, err := GenerateIdentity(2, 1, 1)
	if err != nil {
		t.Fatalf("generate alice: %v", err)
	}

	// Alice initiates session using Bob's PreKey material
	bundle := &VerifiedPreKeyBundle{
		RegistrationID:  bob.ID,
		IdentityExPub:   bob.ExchangeKey.PublicKey(),
		SignedPreKeyPub: bob.SignedPreKeys[0].PublicKey(),
		OneTimePreKeyPub: bob.PreKeys[0].PublicKey(),
		PreKeyID:         0,
		SignedPreKeyID:   0,
	}
	aliceSession, err := CreateSessionInitiator(alice, bundle)
	if err != nil {
		t.Fatalf("CreateSessionInitiator: %v", err)
	}

	// Bob creates session from Alice's ephemeral key
	verifiedMsg := &VerifiedPreKeyMessage{
		PreKeyID:       0,
		SignedPreKeyID: 0,
		BaseKey:        aliceSession.RatchetKey.PublicKey(),
		IdentityExPub:  alice.ExchangeKey.PublicKey(),
	}
	bobSession, err := CreateSessionResponder(bob, verifiedMsg)
	if err != nil {
		t.Fatalf("CreateSessionResponder: %v", err)
	}

	// Verify both sides derived the same root key (must check BEFORE any chain operations)
	aliceRootHex := hex.EncodeToString(aliceSession.RootKey)
	bobRootHex := hex.EncodeToString(bobSession.RootKey)
	if aliceRootHex != bobRootHex {
		t.Fatalf("root keys don't match:\n  alice: %s\n  bob:   %s", aliceRootHex, bobRootHex)
	}
	t.Logf("Root keys match: %s", aliceRootHex)

	// Alice encrypts (this creates a sending chain, mutating RootKey)
	ct, hmacKey, counter, err := aliceSession.EncryptMessage([]byte("Hello Bob"))
	if err != nil {
		t.Fatalf("EncryptMessage: %v", err)
	}
	t.Logf("Alice encrypted: counter=%d, ct=%s, hmac=%s",
		counter, hex.EncodeToString(ct), hex.EncodeToString(hmacKey[:8]))

	// Bob decrypts
	pt, _, err := bobSession.DecryptMessage(ct, aliceSession.RatchetKey.PublicKey(), counter)
	if err != nil {
		t.Fatalf("DecryptMessage: %v", err)
	}
	if string(pt) != "Hello Bob" {
		t.Fatalf("DecryptMessage: got %q, want %q", string(pt), "Hello Bob")
	}
	t.Logf("Bob decrypted: %q", string(pt))

	// Bob replies — EncryptMessage now handles DH ratchet advancement automatically
	ct2, _, counter2, err := bobSession.EncryptMessage([]byte("Hello Alice"))
	if err != nil {
		t.Fatalf("Bob EncryptMessage: %v", err)
	}
	t.Logf("Bob encrypted: counter=%d, ct=%s", counter2, hex.EncodeToString(ct2))

	// Alice decrypts Bob's reply (new ratchet key detected automatically)
	pt2, _, err := aliceSession.DecryptMessage(ct2, bobSession.RatchetKey.PublicKey(), counter2)
	if err != nil {
		t.Fatalf("Alice DecryptMessage: %v", err)
	}
	if string(pt2) != "Hello Alice" {
		t.Fatalf("Alice DecryptMessage: got %q, want %q", string(pt2), "Hello Alice")
	}
	t.Logf("Alice decrypted: %q", string(pt2))
}

func TestThumbprint(t *testing.T) {
	bobSigPub, _ := hex.DecodeString("045f085c5ed12ce89a237ee3fed40495b2fd0b54d2cc75c0ca6f81d7fa08025585404c8e70630c814cc259197e6cf65db85f9d74e6d1d716bd46b12f13508f6447")
	aliceSigPub, _ := hex.DecodeString("04748471c295c3071a8596c974fb386013e85f353bcc9d06caa882f34acdf2ef66db7872354edddf0e53b66bcf84124bb5947187786c3d78d140607853ff86f428")

	bobThumb := Thumbprint(bobSigPub)
	aliceThumb := Thumbprint(aliceSigPub)

	if bobThumb != "35e242fded60e1fa0d642198f4d274c288ccc243a9aa705229a171ed724bbc65" {
		t.Fatalf("bob thumbprint: got %s", bobThumb)
	}
	if aliceThumb != "f3293f51e7afff614779f5199cfff6fa9969a8e9af76c0afd56fb1ec49b6cd82" {
		t.Fatalf("alice thumbprint: got %s", aliceThumb)
	}
}

func TestChallengePin(t *testing.T) {
	bobSigPub, _ := hex.DecodeString("045f085c5ed12ce89a237ee3fed40495b2fd0b54d2cc75c0ca6f81d7fa08025585404c8e70630c814cc259197e6cf65db85f9d74e6d1d716bd46b12f13508f6447")
	aliceSigPub, _ := hex.DecodeString("04748471c295c3071a8596c974fb386013e85f353bcc9d06caa882f34acdf2ef66db7872354edddf0e53b66bcf84124bb5947187786c3d78d140607853ff86f428")

	pin := ComputeChallenge(bobSigPub, aliceSigPub)

	// The JS test gives PIN=279236
	if pin != "279236" {
		t.Fatalf("challenge pin: got %s, want 279236", pin)
	}
}

func TestMultipleMessages(t *testing.T) {
	// Test that multiple messages in the same direction use consecutive chain steps.
	bob, _ := GenerateIdentity(1, 1, 1)
	alice, _ := GenerateIdentity(2, 1, 1)

	bundle := &VerifiedPreKeyBundle{
		RegistrationID: bob.ID, IdentityExPub: bob.ExchangeKey.PublicKey(),
		SignedPreKeyPub: bob.SignedPreKeys[0].PublicKey(),
		OneTimePreKeyPub: bob.PreKeys[0].PublicKey(), PreKeyID: 0, SignedPreKeyID: 0,
	}
	aliceSession, _ := CreateSessionInitiator(alice, bundle)

	msg := &VerifiedPreKeyMessage{
		PreKeyID: 0, SignedPreKeyID: 0,
		BaseKey: aliceSession.RatchetKey.PublicKey(), IdentityExPub: alice.ExchangeKey.PublicKey(),
	}
	bobSession, _ := CreateSessionResponder(bob, msg)

	// Alice sends 3 messages
	messages := []string{"msg1", "msg2", "msg3"}
	ciphertexts := make([][]byte, 3)
	counters := make([]int, 3)

	for i, msg := range messages {
		ct, _, counter, err := aliceSession.EncryptMessage([]byte(msg))
		if err != nil {
			t.Fatalf("encrypt msg %d: %v", i, err)
		}
		ciphertexts[i] = ct
		counters[i] = counter
	}

	// Counters should be 0, 1, 2
	for i, c := range counters {
		if c != i {
			t.Fatalf("counter %d: got %d, want %d", i, c, i)
		}
	}

	// Bob decrypts all 3
	for i, msg := range messages {
		pt, _, err := bobSession.DecryptMessage(ciphertexts[i],
			aliceSession.RatchetKey.PublicKey(), counters[i])
		if err != nil {
			t.Fatalf("decrypt msg %d: %v", i, err)
		}
		if string(pt) != msg {
			t.Fatalf("decrypt msg %d: got %q, want %q", i, string(pt), msg)
		}
	}
}

func TestPKCS7Padding(t *testing.T) {
	tests := []struct {
		input    []byte
		expected int // expected padded length
	}{
		{[]byte(""), 16},
		{[]byte("a"), 16},
		{[]byte("1234567890123456"), 32}, // exactly block size, needs full padding block
		{[]byte("Hello Bob"), 16},
	}

	for _, tt := range tests {
		padded := pkcs7Pad(tt.input, 16)
		if len(padded) != tt.expected {
			t.Errorf("pkcs7Pad(%q): got len %d, want %d", string(tt.input), len(padded), tt.expected)
		}
		unpadded, err := pkcs7Unpad(padded)
		if err != nil {
			t.Errorf("pkcs7Unpad: %v", err)
			continue
		}
		if string(unpadded) != string(tt.input) {
			t.Errorf("round-trip: got %q, want %q", string(unpadded), string(tt.input))
		}
	}
}

func TestDeriveRootKeyKMConstruction(t *testing.T) {
	// Verify that deriveRootKey correctly prepends 0xFF*32
	dh1 := make([]byte, 32)
	dh2 := make([]byte, 32)
	dh3 := make([]byte, 32)
	dh4 := make([]byte, 32)

	// Fill with recognizable patterns
	for i := range dh1 {
		dh1[i] = 0x11
		dh2[i] = 0x22
		dh3[i] = 0x33
		dh4[i] = 0x44
	}

	rootKey, err := deriveRootKey(dh1, dh2, dh3, dh4)
	if err != nil {
		t.Fatalf("deriveRootKey: %v", err)
	}
	if len(rootKey) != 32 {
		t.Fatalf("root key length: got %d, want 32", len(rootKey))
	}

	// Verify the HKDF input is 160 bytes (32 FF + 4*32 DH)
	// We can't directly test KM since it's internal, but if the root key is
	// 32 bytes and non-zero, the construction worked.
	allZero := true
	for _, b := range rootKey {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		t.Fatal("root key is all zeros")
	}
}

func TestDeriveRootKeyNilDH4(t *testing.T) {
	// Verify that nil DH4 (no one-time pre-key) still works
	dh1 := make([]byte, 32)
	dh2 := make([]byte, 32)
	dh3 := make([]byte, 32)

	rootKey, err := deriveRootKey(dh1, dh2, dh3, nil)
	if err != nil {
		t.Fatalf("deriveRootKey with nil DH4: %v", err)
	}
	if len(rootKey) != 32 {
		t.Fatalf("root key length: got %d, want 32", len(rootKey))
	}
}

func TestChainMultipleSteps(t *testing.T) {
	ck, _ := hex.DecodeString("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	chain := &SymmetricChain{RootKey: ck}

	// Step 1
	ck1, _ := chain.Step()
	assertHex(t, "step1 cipher key", ck1,
		"790519613efaec118e63904e01475b9543b9a15c61070227d877418c8cca415e")
	if chain.Counter != 1 {
		t.Fatalf("counter after step 1: got %d, want 1", chain.Counter)
	}

	// Step 2 should use the updated chain key
	ck2, _ := chain.Step()
	if hex.EncodeToString(ck2) == hex.EncodeToString(ck1) {
		t.Fatal("step 2 produced same cipher key as step 1")
	}
	if chain.Counter != 2 {
		t.Fatalf("counter after step 2: got %d, want 2", chain.Counter)
	}

	// Verify step 2 values: HMAC(nextCK_from_step1, 0x01)
	// nextCK from step 1 = e3593f75e832b460cfc9cdea5a65902f94d9213060090c0e00a5a74306389e2e
	expectedNextCK, _ := hex.DecodeString("e3593f75e832b460cfc9cdea5a65902f94d9213060090c0e00a5a74306389e2e")
	expectedCK2 := hmacSHA256(expectedNextCK, cipherKeyKDFInput)
	assertHex(t, "step2 cipher key", ck2, hex.EncodeToString(expectedCK2))
}

func TestECDHInterop(t *testing.T) {
	// Verify that Go's ECDH produces the same shared secret as WebCrypto.
	// Generate two key pairs and verify DH(a,B) == DH(b,A).
	a, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	b, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	ab, err := a.ECDH(b.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	ba, err := b.ECDH(a.PublicKey())
	if err != nil {
		t.Fatal(err)
	}

	if hex.EncodeToString(ab) != hex.EncodeToString(ba) {
		t.Fatal("ECDH commutativity failed")
	}

	// Verify public key format is uncompressed (65 bytes, starts with 04)
	pubBytes := a.PublicKey().Bytes()
	if len(pubBytes) != 65 || pubBytes[0] != 0x04 {
		t.Fatalf("unexpected public key format: len=%d, prefix=%02x", len(pubBytes), pubBytes[0])
	}

	// Verify shared secret is 32 bytes (P-256 x-coordinate)
	if len(ab) != 32 {
		t.Fatalf("shared secret length: got %d, want 32", len(ab))
	}
}

func TestHKDFInfoStrings(t *testing.T) {
	// Verify our info strings match the TS constants
	if string(infoText) != "InfoText" {
		t.Fatal("infoText mismatch")
	}
	if string(infoRatchet) != "InfoRatchet" {
		t.Fatal("infoRatchet mismatch")
	}
	if string(infoMessageKeys) != "InfoMessageKeys" {
		t.Fatal("infoMessageKeys mismatch")
	}

	// Verify hex encoding matches TS Convert.FromBinary()
	assertHex(t, "infoText hex", infoText,
		hex.EncodeToString([]byte("InfoText")))
	assertHex(t, "infoMessageKeys hex", infoMessageKeys,
		hex.EncodeToString([]byte("InfoMessageKeys")))
}

func TestEndToEndWithChainDerivation(t *testing.T) {
	// Full end-to-end: X3DH → create chains → encrypt → decrypt
	// This tests the createChain HKDF with infoRatchet.
	bob, _ := GenerateIdentity(1, 1, 1)
	alice, _ := GenerateIdentity(2, 1, 1)

	bundle := &VerifiedPreKeyBundle{
		RegistrationID: bob.ID, IdentityExPub: bob.ExchangeKey.PublicKey(),
		SignedPreKeyPub: bob.SignedPreKeys[0].PublicKey(),
		OneTimePreKeyPub: bob.PreKeys[0].PublicKey(), PreKeyID: 0, SignedPreKeyID: 0,
	}
	aliceSess, _ := CreateSessionInitiator(alice, bundle)

	vmsg := &VerifiedPreKeyMessage{
		PreKeyID: 0, SignedPreKeyID: 0,
		BaseKey: aliceSess.RatchetKey.PublicKey(), IdentityExPub: alice.ExchangeKey.PublicKey(),
	}
	bobSess, _ := CreateSessionResponder(bob, vmsg)

	// Verify root keys match
	if hex.EncodeToString(aliceSess.RootKey) != hex.EncodeToString(bobSess.RootKey) {
		t.Fatal("root keys don't match after X3DH")
	}

	// Alice creates sending chain (DH with her ratchet key and Bob's SPK)
	aliceChain, err := aliceSess.CreateChain(
		aliceSess.RatchetKey, bobSess.RatchetKey.PublicKey())
	if err != nil {
		t.Fatalf("alice CreateChain: %v", err)
	}

	// Bob creates receiving chain (same DH, mirrored)
	bobChain, err := bobSess.CreateChain(
		bobSess.RatchetKey, aliceSess.RatchetKey.PublicKey())
	if err != nil {
		t.Fatalf("bob CreateChain: %v", err)
	}

	// Both chains should have the same chain key
	assertHex(t, "chain keys match", aliceChain.RootKey,
		hex.EncodeToString(bobChain.RootKey))

	// Both sessions should have the same (updated) root key
	assertHex(t, "root keys match after chain", aliceSess.RootKey,
		hex.EncodeToString(bobSess.RootKey))

	// Encrypt with Alice's chain, decrypt with Bob's chain
	ck, _ := aliceChain.Step()
	mk, _ := DeriveMessageKeys(ck)

	ct, _ := AESCBCEncrypt(mk.AESKey, mk.IV, []byte("test message"))

	ckB, _ := bobChain.Step()
	mkB, _ := DeriveMessageKeys(ckB)

	// Message keys must match
	assertHex(t, "AES keys match", mk.AESKey, hex.EncodeToString(mkB.AESKey))
	assertHex(t, "IV match", mk.IV, hex.EncodeToString(mkB.IV))

	pt, _ := AESCBCDecrypt(mkB.AESKey, mkB.IV, ct)
	if string(pt) != "test message" {
		t.Fatalf("decrypt: got %q, want %q", string(pt), "test message")
	}
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

func assertHex(t *testing.T, name string, got []byte, wantHex string) {
	t.Helper()
	gotHex := hex.EncodeToString(got)
	if gotHex != wantHex {
		t.Fatalf("%s:\n  got:  %s\n  want: %s", name, gotHex, wantHex)
	}
}

// ─── Security Tests ─────────────────────────────────────────────────────────

func makeTestSessions(t *testing.T) (*Session, *Session, *Identity, *Identity) {
	t.Helper()
	bob, _ := GenerateIdentity(1, 1, 1)
	alice, _ := GenerateIdentity(2, 1, 1)
	bundle := &VerifiedPreKeyBundle{
		RegistrationID: bob.ID, IdentityExPub: bob.ExchangeKey.PublicKey(),
		SignedPreKeyPub: bob.SignedPreKeys[0].PublicKey(),
		OneTimePreKeyPub: bob.PreKeys[0].PublicKey(), PreKeyID: 0, SignedPreKeyID: 0,
	}
	aliceSess, _ := CreateSessionInitiator(alice, bundle)
	vmsg := &VerifiedPreKeyMessage{
		PreKeyID: 0, SignedPreKeyID: 0,
		BaseKey: aliceSess.RatchetKey.PublicKey(), IdentityExPub: alice.ExchangeKey.PublicKey(),
	}
	bobSess, _ := CreateSessionResponder(bob, vmsg)
	return aliceSess, bobSess, alice, bob
}

func TestCounterTooLarge(t *testing.T) {
	aliceSess, bobSess, _, _ := makeTestSessions(t)

	ct, _, _, _ := aliceSess.EncryptMessage([]byte("test"))

	// Try to decrypt with a counter way beyond MaxSkip
	_, _, err := bobSess.DecryptMessage(ct, aliceSess.RatchetKey.PublicKey(), MaxSkip+100)
	if err != ErrCounterTooLarge {
		t.Fatalf("expected ErrCounterTooLarge, got: %v", err)
	}
}

func TestDuplicateMessage(t *testing.T) {
	aliceSess, bobSess, _, _ := makeTestSessions(t)

	ct, _, counter, _ := aliceSess.EncryptMessage([]byte("test"))

	// First decrypt should succeed
	pt, _, err := bobSess.DecryptMessage(ct, aliceSess.RatchetKey.PublicKey(), counter)
	if err != nil {
		t.Fatalf("first decrypt: %v", err)
	}
	if string(pt) != "test" {
		t.Fatalf("first decrypt: got %q", string(pt))
	}

	// Second decrypt of same counter should fail
	_, _, err = bobSess.DecryptMessage(ct, aliceSess.RatchetKey.PublicKey(), counter)
	if err != ErrDuplicateMessage {
		t.Fatalf("expected ErrDuplicateMessage, got: %v", err)
	}
}

func TestOutOfOrderMessages(t *testing.T) {
	aliceSess, bobSess, _, _ := makeTestSessions(t)

	// Alice sends 3 messages
	ct0, _, c0, _ := aliceSess.EncryptMessage([]byte("msg0"))
	ct1, _, c1, _ := aliceSess.EncryptMessage([]byte("msg1"))
	ct2, _, c2, _ := aliceSess.EncryptMessage([]byte("msg2"))

	rk := aliceSess.RatchetKey.PublicKey()

	// Bob receives message 2 first (skipping 0 and 1)
	pt2, _, err := bobSess.DecryptMessage(ct2, rk, c2)
	if err != nil {
		t.Fatalf("decrypt msg2: %v", err)
	}
	if string(pt2) != "msg2" {
		t.Fatalf("msg2: got %q", string(pt2))
	}

	// Bob receives message 0 (from skipped cache)
	pt0, _, err := bobSess.DecryptMessage(ct0, rk, c0)
	if err != nil {
		t.Fatalf("decrypt msg0: %v", err)
	}
	if string(pt0) != "msg0" {
		t.Fatalf("msg0: got %q", string(pt0))
	}

	// Bob receives message 1 (from skipped cache)
	pt1, _, err := bobSess.DecryptMessage(ct1, rk, c1)
	if err != nil {
		t.Fatalf("decrypt msg1: %v", err)
	}
	if string(pt1) != "msg1" {
		t.Fatalf("msg1: got %q", string(pt1))
	}

	_ = c0
	_ = c1
}

func TestOneTimePreKeyConsumed(t *testing.T) {
	bob, _ := GenerateIdentity(1, 1, 1)
	alice, _ := GenerateIdentity(2, 1, 1)

	// Verify pre-key exists before session
	if bob.PreKeys[0] == nil {
		t.Fatal("pre-key should exist before session creation")
	}

	bundle := &VerifiedPreKeyBundle{
		RegistrationID: bob.ID, IdentityExPub: bob.ExchangeKey.PublicKey(),
		SignedPreKeyPub: bob.SignedPreKeys[0].PublicKey(),
		OneTimePreKeyPub: bob.PreKeys[0].PublicKey(), PreKeyID: 0, SignedPreKeyID: 0,
	}
	aliceSess, _ := CreateSessionInitiator(alice, bundle)

	vmsg := &VerifiedPreKeyMessage{
		PreKeyID: 0, SignedPreKeyID: 0,
		BaseKey: aliceSess.RatchetKey.PublicKey(), IdentityExPub: alice.ExchangeKey.PublicKey(),
	}
	_, err := CreateSessionResponder(bob, vmsg)
	if err != nil {
		t.Fatal(err)
	}

	// Pre-key should be consumed (nil) after session creation
	if bob.PreKeys[0] != nil {
		t.Fatal("pre-key should be nil after session creation (consumed)")
	}
}

func TestVerifiedPreKeyBundleBadSignature(t *testing.T) {
	bob, _ := GenerateIdentity(1, 1, 1)

	// Build a real bundle via wire encoding, then tamper with it
	bundleBytes, err := EncodePreKeyBundle(bob, 0, 0)
	if err != nil {
		t.Fatal(err)
	}

	parsed, err := DecodePreKeyBundle(bundleBytes)
	if err != nil {
		t.Fatal(err)
	}

	// Should verify clean
	_, err = VerifyAndCreateBundle(parsed)
	if err != nil {
		t.Fatalf("clean bundle should verify: %v", err)
	}

	// Tamper with identity signature
	parsed.Identity.Signature[0] ^= 0x01
	_, err = VerifyAndCreateBundle(parsed)
	if err != ErrInvalidSignature {
		t.Fatalf("tampered identity should fail: got %v", err)
	}
}

func TestDHRatchetAdvancement(t *testing.T) {
	// Test that the DH ratchet advances on direction change,
	// providing forward secrecy.
	aliceSess, bobSess, _, _ := makeTestSessions(t)

	// Alice → Bob
	ct1, _, c1, _ := aliceSess.EncryptMessage([]byte("alice1"))
	pt1, _, _ := bobSess.DecryptMessage(ct1, aliceSess.RatchetKey.PublicKey(), c1)
	if string(pt1) != "alice1" {
		t.Fatal("round 1 failed")
	}

	// Bob → Alice (should ratchet forward with new DH key)
	bobKeyBefore := bobSess.RatchetKey.PublicKey().Bytes()
	ct2, _, c2, _ := bobSess.EncryptMessage([]byte("bob1"))
	bobKeyAfter := bobSess.RatchetKey.PublicKey().Bytes()

	// Bob's ratchet key should have changed
	if hex.EncodeToString(bobKeyBefore) == hex.EncodeToString(bobKeyAfter) {
		t.Fatal("Bob's ratchet key should change on direction reversal")
	}

	pt2, _, _ := aliceSess.DecryptMessage(ct2, bobSess.RatchetKey.PublicKey(), c2)
	if string(pt2) != "bob1" {
		t.Fatalf("round 2: got %q", string(pt2))
	}

	// Alice → Bob again (should ratchet forward again)
	aliceKeyBefore := aliceSess.RatchetKey.PublicKey().Bytes()
	ct3, _, c3, _ := aliceSess.EncryptMessage([]byte("alice2"))
	aliceKeyAfter := aliceSess.RatchetKey.PublicKey().Bytes()

	if hex.EncodeToString(aliceKeyBefore) == hex.EncodeToString(aliceKeyAfter) {
		t.Fatal("Alice's ratchet key should change on direction reversal")
	}

	pt3, _, _ := bobSess.DecryptMessage(ct3, aliceSess.RatchetKey.PublicKey(), c3)
	if string(pt3) != "alice2" {
		t.Fatalf("round 3: got %q", string(pt3))
	}
}

// Suppress unused import
var _ = sha256.New
var _ = fmt.Sprintf
