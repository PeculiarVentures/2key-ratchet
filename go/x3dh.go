package ratchet

import (
	"crypto/ecdh"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"math/big"

	"golang.org/x/crypto/hkdf"
)

// ─── Challenge PIN ───────────────────────────────────────────────────────────

// ComputeChallenge generates the 6-digit verification PIN from both parties'
// identity signing public keys.
//
// The JS implementation:
//   serverDigest = SHA256(serverSigningPubXY).toHex()
//   clientDigest = SHA256(clientSigningPubXY).toHex()
//   combined = fromHex(serverDigest + clientDigest)
//   digest = SHA256(combined)
//   pin = parseInt(digest.toHex(), 16).toString().substr(2, 6)
//
// The key subtlety: parseInt on a 64-char hex string produces a float64 like
// 9.279236733259276e+76, and toString() renders it in scientific notation.
// substr(2,6) then extracts 6 digits from that notation string, skipping
// the leading digit and the dot.
func ComputeChallenge(serverSigningPubRaw, clientSigningPubRaw []byte) string {
	serverThumb := Thumbprint(serverSigningPubRaw)
	clientThumb := Thumbprint(clientSigningPubRaw)

	combinedHex := serverThumb + clientThumb
	combinedBytes, _ := hex.DecodeString(combinedHex)

	digest := sha256.Sum256(combinedBytes)
	digestHex := hex.EncodeToString(digest[:])

	// Replicate JS: parseInt(digestHex, 16) as float64
	// JS parseInt reads the hex string and converts to float64, losing precision
	// beyond ~15-16 significant decimal digits. We need the same float64 value.
	//
	// Parse the hex as a big.Float with 53-bit precision (float64 equivalent),
	// then format it the way JS Number.toString() would.
	n := new(big.Int)
	n.SetString(digestHex, 16)

	// Convert to float64 (same precision loss as JS parseInt)
	f := new(big.Float).SetPrec(53).SetInt(n)
	f64, _ := f.Float64()

	// Format the same way JS does: %g with enough precision
	// JS Number.toString() uses the shortest representation that round-trips.
	// Go's %g with default precision does the same thing.
	s := fmt.Sprintf("%g", f64)

	// Extract substr(2, 6) — 6 chars starting at index 2
	if len(s) < 8 {
		return "000000"
	}
	return s[2:8]
}

// ─── X3DH Key Agreement ──────────────────────────────────────────────────────

// AuthenticateA performs the X3DH key agreement from the initiator's (Alice's) side.
//
// Parameters match authenticateA(IKa, EKa, IKb, SPKb, OPKb) in 2key-ratchet:
//   IKa  = initiator's identity (has exchangeKey)
//   EKa  = initiator's ephemeral ratchet key
//   IKb  = responder's identity exchange public key
//   SPKb = responder's signed pre-key public key
//   OPKb = responder's one-time pre-key public key (may be nil)
//
// Returns the root key (32 bytes).
func AuthenticateA(
	identityExchangePriv *ecdh.PrivateKey, // IKa.exchangeKey
	ephemeralPriv *ecdh.PrivateKey,         // EKa (currentRatchetKey)
	remoteIdentityExPub *ecdh.PublicKey,    // IKb (identity exchange)
	remoteSignedPreKeyPub *ecdh.PublicKey,  // SPKb
	remoteOneTimePreKeyPub *ecdh.PublicKey, // OPKb (may be nil)
) ([]byte, error) {
	// DH1 = DH(IKa.exchangeKey, SPKb)
	dh1, err := identityExchangePriv.ECDH(remoteSignedPreKeyPub)
	if err != nil {
		return nil, fmt.Errorf("DH1: %w", err)
	}

	// DH2 = DH(EKa, IKb)
	dh2, err := ephemeralPriv.ECDH(remoteIdentityExPub)
	if err != nil {
		return nil, fmt.Errorf("DH2: %w", err)
	}

	// DH3 = DH(EKa, SPKb)
	dh3, err := ephemeralPriv.ECDH(remoteSignedPreKeyPub)
	if err != nil {
		return nil, fmt.Errorf("DH3: %w", err)
	}

	// DH4 = DH(EKa, OPKb) if OPKb is provided
	var dh4 []byte
	if remoteOneTimePreKeyPub != nil {
		dh4, err = ephemeralPriv.ECDH(remoteOneTimePreKeyPub)
		if err != nil {
			return nil, fmt.Errorf("DH4: %w", err)
		}
	}

	return deriveRootKey(dh1, dh2, dh3, dh4)
}

// AuthenticateB performs X3DH from the responder's (Bob's) side.
//
// Parameters match authenticateB(IKb, SPKb, IKa, EKa, OPKb) in 2key-ratchet:
//   IKb  = responder's identity (has exchangeKey)
//   SPKb = responder's signed pre-key
//   IKa  = initiator's identity exchange public key
//   EKa  = initiator's ephemeral ratchet key public key
//   OPKb = responder's one-time pre-key private (may be nil)
func AuthenticateB(
	identityExchangePriv *ecdh.PrivateKey, // IKb.exchangeKey
	signedPreKeyPriv *ecdh.PrivateKey,      // SPKb
	remoteIdentityExPub *ecdh.PublicKey,    // IKa (identity exchange)
	remoteEphemeralPub *ecdh.PublicKey,      // EKa (sender's ratchet key)
	oneTimePreKeyPriv *ecdh.PrivateKey,      // OPKb (may be nil)
) ([]byte, error) {
	// DH1 = DH(SPKb, IKa)
	dh1, err := signedPreKeyPriv.ECDH(remoteIdentityExPub)
	if err != nil {
		return nil, fmt.Errorf("DH1: %w", err)
	}

	// DH2 = DH(IKb.exchangeKey, EKa)
	dh2, err := identityExchangePriv.ECDH(remoteEphemeralPub)
	if err != nil {
		return nil, fmt.Errorf("DH2: %w", err)
	}

	// DH3 = DH(SPKb, EKa)
	dh3, err := signedPreKeyPriv.ECDH(remoteEphemeralPub)
	if err != nil {
		return nil, fmt.Errorf("DH3: %w", err)
	}

	// DH4 = DH(OPKb, EKa)
	var dh4 []byte
	if oneTimePreKeyPriv != nil {
		dh4, err = oneTimePreKeyPriv.ECDH(remoteEphemeralPub)
		if err != nil {
			return nil, fmt.Errorf("DH4: %w", err)
		}
	}

	return deriveRootKey(dh1, dh2, dh3, dh4)
}

// deriveRootKey builds KM and runs HKDF to produce the root key.
// KM = FF(32) || DH1 || DH2 || DH3 || DH4
// rootKey = HKDF-SHA256(KM, salt=zeros(32), info="InfoText", length=32)
func deriveRootKey(dh1, dh2, dh3, dh4 []byte) ([]byte, error) {
	// 32 bytes of 0xFF prefix (matches the _F construction in 2key-ratchet)
	ff := make([]byte, 32)
	for i := range ff {
		ff[i] = 0xFF
	}

	km := make([]byte, 0, 32+len(dh1)+len(dh2)+len(dh3)+len(dh4))
	km = append(km, ff...)
	km = append(km, dh1...)
	km = append(km, dh2...)
	km = append(km, dh3...)
	km = append(km, dh4...)

	// HKDF-SHA256: salt = 32 zero bytes, info = "InfoText", derive 32 bytes
	salt := make([]byte, 32)
	reader := hkdf.New(sha256.New, km, salt, infoText)
	rootKey := make([]byte, 32)
	if _, err := io.ReadFull(reader, rootKey); err != nil {
		return nil, fmt.Errorf("HKDF: %w", err)
	}

	return rootKey, nil
}
