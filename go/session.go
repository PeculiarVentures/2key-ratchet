package ratchet

import (
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"io"
	"sync"
	"time"

	"golang.org/x/crypto/hkdf"
)

// ─── Session ─────────────────────────────────────────────────────────────────

// DefaultSkippedKeyTTL is how long skipped message keys are retained
// before being pruned. Prevents stale keys from accumulating indefinitely
// in long-lived sessions.
const DefaultSkippedKeyTTL = 1 * time.Hour

// skippedKeyEntry pairs a cached message key with its creation time
// for TTL-based expiry.
type skippedKeyEntry struct {
	Keys     *MessageKeys
	CachedAt time.Time
}

// Session manages the Double Ratchet state for a single peer.
type Session struct {
	mu sync.Mutex

	Identity       *Identity
	RemoteIdentity *RemoteIdentity
	RootKey        []byte // current ratchet root key (32 bytes, HMAC key material)
	CurrentStep    *DHRatchetStep
	Steps          []*DHRatchetStep
	RatchetKey     *ecdh.PrivateKey // our current ratchet key pair
	Counter        int

	RemotePreKeyID       int
	RemotePreKeySignedID int

	// Signing key XY (64 bytes) for HMAC verification on MessageSignedProtocol.
	// RemoteSigningKeyXY = remote peer's identity signing public key (X||Y)
	// LocalSigningKeyXY = our identity signing public key (X||Y)
	RemoteSigningKeyXY []byte
	LocalSigningKeyXY  []byte

	// SkippedKeys caches message keys for out-of-order delivery.
	// Key: "ratchetKeyHex:counter", Value: *skippedKeyEntry
	// Bounded by MaxSkip count and SkippedKeyTTL time.
	SkippedKeys    map[string]*skippedKeyEntry
	SkippedKeyTTL  time.Duration // default: 1 hour
}

// VerifiedPreKeyBundle holds a parsed and signature-verified PreKeyBundle.
// The only way to construct one is through VerifyPreKeyBundle(), which
// enforces identity and pre-key signature verification.
type VerifiedPreKeyBundle struct {
	RegistrationID     int
	IdentityExPub      *ecdh.PublicKey
	IdentitySigningXY  []byte
	SignedPreKeyPub    *ecdh.PublicKey
	OneTimePreKeyPub   *ecdh.PublicKey // may be nil
	PreKeyID           int
	SignedPreKeyID     int
}

// VerifiedPreKeyMessage holds a parsed and signature-verified PreKeyMessage.
type VerifiedPreKeyMessage struct {
	RegistrationID     int
	PreKeyID           int
	SignedPreKeyID     int
	BaseKey            *ecdh.PublicKey
	IdentityExPub      *ecdh.PublicKey
	IdentitySigningXY  []byte
	SignedMessage      *ParsedMessageSigned
	SignedMessageRaw   []byte // raw bytes for HMAC verification
}

// VerifyAndCreateBundle verifies all signatures on a parsed PreKeyBundle
// and returns a VerifiedPreKeyBundle that can be used for session creation.
func VerifyAndCreateBundle(bundle *ParsedPreKeyBundle) (*VerifiedPreKeyBundle, error) {
	if bundle.Identity == nil || bundle.PreKeySigned == nil {
		return nil, fmt.Errorf("bundle missing identity or signed pre-key")
	}

	// Verify identity signature (signing key signed the exchange key)
	if !VerifyIdentitySignature(bundle.Identity.SigningKeyXY, bundle.Identity.ExchangeKeyXY, bundle.Identity.Signature) {
		return nil, ErrInvalidSignature
	}

	// Verify signed pre-key signature
	if !VerifyPreKeySignature(bundle.Identity.SigningKeyXY, bundle.PreKeySigned.KeyXY, bundle.PreKeySigned.Signature) {
		return nil, ErrInvalidSignature
	}

	// Parse public keys
	exPub, err := parseP256PublicKeyXY(bundle.Identity.ExchangeKeyXY)
	if err != nil {
		return nil, fmt.Errorf("parse identity exchange key: %w", err)
	}
	spkPub, err := parseP256PublicKeyXY(bundle.PreKeySigned.KeyXY)
	if err != nil {
		return nil, fmt.Errorf("parse signed pre-key: %w", err)
	}

	var opkPub *ecdh.PublicKey
	if bundle.PreKey != nil && len(bundle.PreKey.KeyXY) == 64 {
		opkPub, err = parseP256PublicKeyXY(bundle.PreKey.KeyXY)
		if err != nil {
			return nil, fmt.Errorf("parse one-time pre-key: %w", err)
		}
	}

	preKeyID := -1
	if bundle.PreKey != nil {
		preKeyID = int(bundle.PreKey.ID)
	}

	return &VerifiedPreKeyBundle{
		RegistrationID:    int(bundle.RegistrationID),
		IdentityExPub:     exPub,
		IdentitySigningXY: bundle.Identity.SigningKeyXY,
		SignedPreKeyPub:   spkPub,
		OneTimePreKeyPub:  opkPub,
		PreKeyID:          preKeyID,
		SignedPreKeyID:    int(bundle.PreKeySigned.ID),
	}, nil
}

// VerifyAndCreatePreKeyMessage verifies all signatures on a parsed PreKeyMessage.
func VerifyAndCreatePreKeyMessage(msg *ParsedPreKeyMessage) (*VerifiedPreKeyMessage, error) {
	if msg.Identity == nil || msg.SignedMessage == nil || msg.SignedMessage.Message == nil {
		return nil, fmt.Errorf("message missing required fields")
	}

	// Verify sender's identity signature
	if !VerifyIdentitySignature(msg.Identity.SigningKeyXY, msg.Identity.ExchangeKeyXY, msg.Identity.Signature) {
		return nil, ErrInvalidSignature
	}

	// Parse public keys
	exPub, err := parseP256PublicKeyXY(msg.Identity.ExchangeKeyXY)
	if err != nil {
		return nil, fmt.Errorf("parse identity exchange key: %w", err)
	}
	baseKey, err := parseP256PublicKeyXY(msg.BaseKeyXY)
	if err != nil {
		return nil, fmt.Errorf("parse base key: %w", err)
	}

	return &VerifiedPreKeyMessage{
		RegistrationID:    int(msg.RegistrationID),
		PreKeyID:          int(msg.PreKeyID),
		SignedPreKeyID:    int(msg.PreKeySignedID),
		BaseKey:           baseKey,
		IdentityExPub:     exPub,
		IdentitySigningXY: msg.Identity.SigningKeyXY,
		SignedMessage:      msg.SignedMessage,
	}, nil
}

// CreateSessionInitiator builds a session from a verified PreKeyBundle (Alice/initiator side).
func CreateSessionInitiator(
	identity *Identity,
	bundle *VerifiedPreKeyBundle,
) (*Session, error) {
	// Generate ephemeral ratchet key
	ratchetKey, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate ratchet key: %w", err)
	}

	// X3DH key agreement
	rootKey, err := AuthenticateA(
		identity.ExchangeKey,
		ratchetKey,
		bundle.IdentityExPub,
		bundle.SignedPreKeyPub,
		bundle.OneTimePreKeyPub,
	)
	if err != nil {
		return nil, err
	}

	return &Session{
		Identity:   identity,
		RootKey:    rootKey,
		RatchetKey: ratchetKey,
		CurrentStep: &DHRatchetStep{
			RemoteRatchetKey: bundle.SignedPreKeyPub,
		},
		RemotePreKeyID:       bundle.PreKeyID,
		RemotePreKeySignedID: bundle.SignedPreKeyID,
		RemoteSigningKeyXY:   bundle.IdentitySigningXY,
		LocalSigningKeyXY:    pubKeyToXY(identity.SigningPublicKeyRaw()),
		SkippedKeys:   make(map[string]*skippedKeyEntry),
		SkippedKeyTTL: DefaultSkippedKeyTTL,
	}, nil
}

// CreateSessionResponder builds a session from a verified PreKeyMessage (Bob/responder side).
// Consumes the one-time pre-key by setting it to nil in the identity after use.
func CreateSessionResponder(
	identity *Identity,
	msg *VerifiedPreKeyMessage,
) (*Session, error) {
	if msg.SignedPreKeyID >= len(identity.SignedPreKeys) {
		return nil, fmt.Errorf("signed pre-key %d not found", msg.SignedPreKeyID)
	}

	var oneTimePreKey *ecdh.PrivateKey
	if msg.PreKeyID >= 0 && msg.PreKeyID < len(identity.PreKeys) {
		oneTimePreKey = identity.PreKeys[msg.PreKeyID]
		// Consume the one-time pre-key to prevent replay
		identity.PreKeys[msg.PreKeyID] = nil
	}

	rootKey, err := AuthenticateB(
		identity.ExchangeKey,
		identity.SignedPreKeys[msg.SignedPreKeyID],
		msg.IdentityExPub,
		msg.BaseKey,
		oneTimePreKey,
	)
	if err != nil {
		return nil, err
	}

	return &Session{
		Identity:           identity,
		RootKey:            rootKey,
		RatchetKey:         identity.SignedPreKeys[msg.SignedPreKeyID],
		CurrentStep:        &DHRatchetStep{},
		RemoteSigningKeyXY: msg.IdentitySigningXY,
		LocalSigningKeyXY:  pubKeyToXY(identity.SigningPublicKeyRaw()),
		SkippedKeys:   make(map[string]*skippedKeyEntry),
		SkippedKeyTTL: DefaultSkippedKeyTTL,
	}, nil
}

// CreateChain derives a new symmetric chain from the DH ratchet.
func (s *Session) CreateChain(ourPriv *ecdh.PrivateKey, theirPub *ecdh.PublicKey) (*SymmetricChain, error) {
	derivedBytes, err := ourPriv.ECDH(theirPub)
	if err != nil {
		return nil, fmt.Errorf("DH for chain: %w", err)
	}

	reader := hkdf.New(sha256.New, derivedBytes, s.RootKey, infoRatchet)

	newRootKey := make([]byte, 32)
	chainKey := make([]byte, 32)
	if _, err := io.ReadFull(reader, newRootKey); err != nil {
		return nil, err
	}
	if _, err := io.ReadFull(reader, chainKey); err != nil {
		return nil, err
	}

	s.RootKey = newRootKey
	return &SymmetricChain{RootKey: chainKey}, nil
}

// skippedKeyID returns the cache key for a skipped message key.
func skippedKeyID(ratchetKeyPub *ecdh.PublicKey, counter int) string {
	return hex.EncodeToString(ratchetKeyPub.Bytes()) + ":" + fmt.Sprintf("%d", counter)
}

// EncryptMessage encrypts a plaintext message using the sending chain.
// Returns the ciphertext and the HMAC key for signing the outer message.
//
// Matches AsymmetricRatchet.encrypt() in TS:
// - If we have a receiving chain but no sending chain, ratchet forward
//   with a new DH key (providing forward secrecy)
// - Create sending chain if needed
// - Step the chain and encrypt
func (s *Session) EncryptMessage(plaintext []byte) (ciphertext []byte, msgHMACKey []byte, counter int, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// DH ratchet step: if we received a message (have receiving chain)
	// but haven't sent yet (no sending chain), generate new ratchet key.
	// This matches the TS behavior in AsymmetricRatchet.encrypt().
	if s.CurrentStep.ReceivingChain != nil && s.CurrentStep.SendingChain == nil {
		s.Counter++
		newKey, err := ecdh.P256().GenerateKey(rand.Reader)
		if err != nil {
			return nil, nil, 0, fmt.Errorf("generate ratchet key: %w", err)
		}
		s.RatchetKey = newKey
	}

	// Ensure we have a sending chain
	if s.CurrentStep.SendingChain == nil {
		if s.CurrentStep.RemoteRatchetKey == nil {
			return nil, nil, 0, fmt.Errorf("no remote ratchet key set")
		}
		chain, err := s.CreateChain(s.RatchetKey, s.CurrentStep.RemoteRatchetKey)
		if err != nil {
			return nil, nil, 0, err
		}
		s.CurrentStep.SendingChain = chain
	}

	// Step the chain
	cipherKey, err := s.CurrentStep.SendingChain.Step()
	if err != nil {
		return nil, nil, 0, err
	}

	// Derive message keys
	mk, err := DeriveMessageKeys(cipherKey)
	if err != nil {
		return nil, nil, 0, err
	}

	// Encrypt with AES-256-CBC
	ciphertext, err = AESCBCEncrypt(mk.AESKey, mk.IV, plaintext)
	if err != nil {
		return nil, nil, 0, err
	}

	return ciphertext, mk.HMACKey, s.CurrentStep.SendingChain.Counter - 1, nil
}

// DecryptMessage decrypts a received message using the receiving chain.
//
// Security properties:
// - Validates counter is within MaxSkip bound (prevents DoS)
// - Checks for duplicate counters (prevents replay)
// - Caches skipped message keys for out-of-order delivery
// - Performs DH ratchet step when new remote ratchet key is seen
func (s *Session) DecryptMessage(ciphertext []byte, remoteRatchetKey *ecdh.PublicKey, msgCounter int) ([]byte, []byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	mk, err := s.deriveMessageKeysLocked(remoteRatchetKey, msgCounter)
	if err != nil {
		return nil, nil, err
	}

	plaintext, err := AESCBCDecrypt(mk.AESKey, mk.IV, ciphertext)
	if err != nil {
		return nil, nil, err
	}

	return plaintext, mk.HMACKey, nil
}

// deriveMessageKeysLocked performs chain stepping and returns the MessageKeys
// for the given remote ratchet key and counter. Must be called with s.mu held.
//
// This is separated from decryption so that DecryptSignedMessage can verify
// the HMAC BEFORE decrypting the ciphertext (MAC-then-decrypt ordering),
// preventing padding oracle attacks.
func (s *Session) deriveMessageKeysLocked(remoteRatchetKey *ecdh.PublicKey, msgCounter int) (*MessageKeys, error) {
	// Prune expired skipped keys
	if s.SkippedKeyTTL > 0 {
		now := time.Now()
		for id, entry := range s.SkippedKeys {
			if now.Sub(entry.CachedAt) > s.SkippedKeyTTL {
				delete(s.SkippedKeys, id)
			}
		}
	}

	// Check for skipped key (out-of-order message)
	skID := skippedKeyID(remoteRatchetKey, msgCounter)
	if entry, ok := s.SkippedKeys[skID]; ok {
		delete(s.SkippedKeys, skID)
		return entry.Keys, nil
	}

	// Determine if we need a new receiving chain.
	needNewStep := false

	if s.CurrentStep.RemoteRatchetKey != nil {
		currentKeyBytes := s.CurrentStep.RemoteRatchetKey.Bytes()
		newKeyBytes := remoteRatchetKey.Bytes()
		if subtle.ConstantTimeCompare(currentKeyBytes, newKeyBytes) != 1 {
			needNewStep = true
		}
	}

	if needNewStep {
		// New remote ratchet key: push old step, create new one
		if s.CurrentStep.ReceivingChain != nil {
			if err := s.cacheSkippedKeys(s.CurrentStep.RemoteRatchetKey, s.CurrentStep.ReceivingChain, MaxSkip); err != nil {
				return nil, err
			}
		}
		s.Steps = append(s.Steps, s.CurrentStep)
		if len(s.Steps) > maxRatchetStackSize {
			s.Steps = s.Steps[len(s.Steps)-maxRatchetStackSize:]
		}
		s.CurrentStep = &DHRatchetStep{
			RemoteRatchetKey: remoteRatchetKey,
		}
	}

	if s.CurrentStep.ReceivingChain == nil {
		s.CurrentStep.RemoteRatchetKey = remoteRatchetKey
		chain, err := s.CreateChain(s.RatchetKey, remoteRatchetKey)
		if err != nil {
			return nil, err
		}
		s.CurrentStep.ReceivingChain = chain
	}

	// Validate counter bounds
	if msgCounter < s.CurrentStep.ReceivingChain.Counter {
		return nil, ErrDuplicateMessage
	}
	skip := msgCounter - s.CurrentStep.ReceivingChain.Counter
	if skip > MaxSkip {
		return nil, ErrCounterTooLarge
	}

	// Cache skipped keys up to the target counter
	if err := s.cacheSkippedKeys(remoteRatchetKey, s.CurrentStep.ReceivingChain, msgCounter); err != nil {
		return nil, err
	}

	// Step to the target counter
	cipherKey, err := s.CurrentStep.ReceivingChain.Step()
	if err != nil {
		return nil, err
	}

	return DeriveMessageKeys(cipherKey)
}

// DecryptSignedMessage decrypts a ParsedMessageSigned, verifying the HMAC
// signature BEFORE decrypting the ciphertext.
//
// This implements MAC-then-decrypt ordering to prevent padding oracle attacks:
//   1. Derive message keys (AES + HMAC + IV) from the receiving chain
//   2. Verify HMAC over receiverKeyXY || senderKeyXY || messageProtoRaw
//   3. Only if HMAC passes, decrypt the AES-CBC ciphertext
//
// The signed data uses the ORIGINAL MessageProtocol bytes from the wire
// (preserved in ParsedMessageSigned.MessageRaw), not re-encoded bytes.
func (s *Session) DecryptSignedMessage(sm *ParsedMessageSigned) ([]byte, error) {
	if sm.Message == nil || sm.MessageRaw == nil {
		return nil, fmt.Errorf("signed message missing message or raw bytes")
	}

	// Parse the sender's ratchet key
	remoteRatchetKey, err := parseP256PublicKeyXY(sm.Message.SenderRatchetKeyXY)
	if err != nil {
		return nil, fmt.Errorf("parse sender ratchet key: %w", err)
	}

	// Step 1: Derive message keys WITHOUT decrypting
	s.mu.Lock()
	mk, err := s.deriveMessageKeysLocked(remoteRatchetKey, int(sm.Message.Counter))
	s.mu.Unlock()
	if err != nil {
		return nil, err
	}

	// Step 2: Verify HMAC BEFORE decryption.
	// Signing keys are required for HMAC verification. Sessions created through
	// CreateSessionInitiator or CreateSessionResponder always have them set.
	if len(s.LocalSigningKeyXY) == 0 || len(s.RemoteSigningKeyXY) == 0 {
		return nil, fmt.Errorf("ratchet: session missing signing keys for HMAC verification")
	}
	signedData := make([]byte, 0, len(s.LocalSigningKeyXY)+len(s.RemoteSigningKeyXY)+len(sm.MessageRaw))
	signedData = append(signedData, s.LocalSigningKeyXY...)
	signedData = append(signedData, s.RemoteSigningKeyXY...)
	signedData = append(signedData, sm.MessageRaw...)

	expected := hmacSHA256(mk.HMACKey, signedData)

	if subtle.ConstantTimeCompare(expected, sm.Signature) != 1 {
		return nil, ErrHMACVerifyFailed
	}

	// Step 3: Decrypt only after HMAC verification passes
	plaintext, err := AESCBCDecrypt(mk.AESKey, mk.IV, sm.Message.CipherText)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

// cacheSkippedKeys steps the chain and caches message keys for counters
// from the chain's current counter up to (but not including) targetCounter.
func (s *Session) cacheSkippedKeys(ratchetKey *ecdh.PublicKey, chain *SymmetricChain, targetCounter int) error {
	for chain.Counter < targetCounter {
		if len(s.SkippedKeys) >= MaxSkip {
			return nil
		}
		cipherKey, err := chain.Step()
		if err != nil {
			return err
		}
		mk, err := DeriveMessageKeys(cipherKey)
		if err != nil {
			return err
		}
		skID := skippedKeyID(ratchetKey, chain.Counter-1)
		s.SkippedKeys[skID] = &skippedKeyEntry{Keys: mk, CachedAt: time.Now()}
	}
	return nil
}

