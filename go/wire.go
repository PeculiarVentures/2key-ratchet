package ratchet

// Wire protocol encoding/decoding for 2key-ratchet protobuf messages.
//
// Field ID reference (from the TS source decorators):
//
// BaseProtocol:
//   version = field 0 (uint32, default 1)
//
// IdentityProtocol (extends BaseProtocol):
//   signingKey   = field 1 (bytes, ECDSAPublicKeyConverter = X||Y 64 bytes)
//   exchangeKey  = field 2 (bytes, ECDHPublicKeyConverter = X||Y 64 bytes)
//   signature    = field 3 (bytes)
//   createdAt    = field 4 (bytes, DateConverter = ISO string as UTF-8)
//
// PreKeyProtocol (extends BaseProtocol):
//   id  = field 1 (uint32)
//   key = field 2 (bytes, ECDHPublicKeyConverter = X||Y 64 bytes)
//
// PreKeySignedProtocol (extends PreKeyProtocol):
//   id        = field 1 (uint32)
//   key       = field 2 (bytes)
//   signature = field 3 (bytes, ArrayBufferConverter)
//
// PreKeyBundleProtocol (extends BaseProtocol):
//   registrationId = field 1 (uint32)
//   identity       = field 2 (bytes, parser: IdentityProtocol)
//   preKey         = field 3 (bytes, parser: PreKeyProtocol)
//   preKeySigned   = field 4 (bytes, parser: PreKeySignedProtocol)
//
// PreKeyMessageProtocol (extends BaseProtocol):
//   registrationId = field 1 (uint32)
//   preKeyId       = field 2 (uint32)
//   preKeySignedId = field 3 (uint32)
//   baseKey        = field 4 (bytes, ECDHPublicKeyConverter = X||Y 64 bytes)
//   identity       = field 5 (bytes, parser: IdentityProtocol)
//   signedMessage  = field 6 (bytes, parser: MessageSignedProtocol)
//
// MessageSignedProtocol (extends BaseProtocol):
//   receiverKey = field 1 (bytes, ECDSAPublicKeyConverter = X||Y 64 bytes)
//   senderKey   = field 2 (bytes -- WAIT, see below)
//   message     = field 2 (bytes, parser: MessageProtocol)  -- ACTUALLY field 2
//   signature   = field 3 (bytes)
//
// NOTE: In the TS source, MessageSignedProtocol inherits from BaseProtocol
// which has version at field 0. Then it declares:
//   receiverKey at id=1
//   message at id=2 (parser: MessageProtocol)  -- senderKey is NOT in the protobuf schema!
//   signature at id=3
// senderKey is set programmatically but NOT serialized as a protobuf field.
//
// MessageProtocol (extends BaseProtocol):
//   senderRatchetKey = field 1 (bytes, ECDHPublicKeyConverter = X||Y 64 bytes)
//   counter          = field 2 (uint32)
//   previousCounter  = field 3 (uint32)
//   cipherText       = field 4 (bytes, ArrayBufferConverter)
//
// IMPORTANT: BaseProtocol.version uses field id 0. Standard protobuf field IDs
// start at 1. Field 0 has tag byte 0x00 (field 0, wire type 0 = varint).
// tsprotobuf/protobufjs handles this fine.

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha512"
	cryptosubtle "crypto/subtle"
	"encoding/binary"
	"fmt"
	"math/big"
	"time"
)

// ─── Protobuf Encoding Primitives ────────────────────────────────────────────

func pbVarint(v uint64) []byte {
	buf := make([]byte, binary.MaxVarintLen64)
	n := binary.PutUvarint(buf, v)
	return buf[:n]
}

func pbField(fieldNum int, wireType int, data []byte) []byte {
	tag := uint64(fieldNum<<3) | uint64(wireType)
	var out []byte
	out = append(out, pbVarint(tag)...)
	if wireType == 2 { // length-delimited
		out = append(out, pbVarint(uint64(len(data)))...)
	}
	out = append(out, data...)
	return out
}

func pbUint32Field(fieldNum int, v uint32) []byte {
	return pbField(fieldNum, 0, pbVarint(uint64(v)))
}

func pbBytesField(fieldNum int, data []byte) []byte {
	return pbField(fieldNum, 2, data)
}

// pubKeyToXY converts an uncompressed P-256 public key (04||X||Y, 65 bytes)
// to X||Y format (64 bytes), matching ECPublicKey.serialize() in 2key-ratchet.
func pubKeyToXY(uncompressed []byte) []byte {
	if len(uncompressed) == 65 && uncompressed[0] == 0x04 {
		return uncompressed[1:]
	}
	if len(uncompressed) == 64 {
		return uncompressed
	}
	return uncompressed
}

// parseP256PublicKeyXY parses an X||Y (64 byte) EC point into an ECDH public key.
// Avoids allocating a temporary 65-byte uncompressed buffer on every call
// by reusing a stack-sized array.
func parseP256PublicKeyXY(xy []byte) (*ecdh.PublicKey, error) {
	if len(xy) == 65 && xy[0] == 0x04 {
		return ecdh.P256().NewPublicKey(xy)
	}
	if len(xy) != 64 {
		return nil, fmt.Errorf("invalid XY length: %d", len(xy))
	}
	var buf [65]byte
	buf[0] = 0x04
	copy(buf[1:], xy)
	return ecdh.P256().NewPublicKey(buf[:])
}

// ─── Identity Protocol ───────────────────────────────────────────────────────

// EncodeIdentityProtocol serializes an IdentityProtocol message.
func EncodeIdentityProtocol(identity *Identity) ([]byte, error) {
	sigPubXY := pubKeyToXY(identity.SigningPublicKeyRaw())
	exPubXY := pubKeyToXY(identity.ExchangePublicKeyRaw())

	// Sign the exchange key with the signing key (ECDSA-P256 with SHA-512,
	// matching Curve.DIGEST_ALGORITHM in 2key-ratchet)
	hash := sha512.Sum512(exPubXY)
	derSig, err := ecdsa.SignASN1(rand.Reader, identity.SigningKey, hash[:])
	if err != nil {
		return nil, fmt.Errorf("sign exchange key: %w", err)
	}
	sig := derToP1363(derSig)

	now := time.Now().UTC().Format(time.RFC3339Nano)

	var buf []byte
	// field 0: version (note: field 0 is unusual but matches BaseProtocol)
	buf = append(buf, pbUint32Field(0, 1)...)
	// field 1: signingKey (X||Y, 64 bytes)
	buf = append(buf, pbBytesField(1, sigPubXY)...)
	// field 2: exchangeKey (X||Y, 64 bytes)
	buf = append(buf, pbBytesField(2, exPubXY)...)
	// field 3: signature
	buf = append(buf, pbBytesField(3, sig)...)
	// field 4: createdAt (ISO date string as bytes)
	buf = append(buf, pbBytesField(4, []byte(now))...)

	return buf, nil
}

// EncodePreKeyProtocol serializes a PreKeyProtocol message.
func EncodePreKeyProtocol(id int, pubKey *ecdh.PublicKey) []byte {
	xy := pubKeyToXY(pubKey.Bytes())
	var buf []byte
	buf = append(buf, pbUint32Field(0, 1)...)  // version
	buf = append(buf, pbUint32Field(1, uint32(id))...) // id
	buf = append(buf, pbBytesField(2, xy)...)  // key
	return buf
}

// EncodePreKeySignedProtocol serializes a PreKeySignedProtocol message.
func EncodePreKeySignedProtocol(id int, pubKey *ecdh.PublicKey, signingKey *ecdsa.PrivateKey) ([]byte, error) {
	xy := pubKeyToXY(pubKey.Bytes())

	// Sign the pre-key public key (ECDSA-P256 with SHA-512)
	hash := sha512.Sum512(xy)
	derSig, err := ecdsa.SignASN1(rand.Reader, signingKey, hash[:])
	if err != nil {
		return nil, err
	}
	sig := derToP1363(derSig)

	var buf []byte
	buf = append(buf, pbUint32Field(0, 1)...)  // version
	buf = append(buf, pbUint32Field(1, uint32(id))...) // id
	buf = append(buf, pbBytesField(2, xy)...)  // key
	buf = append(buf, pbBytesField(3, sig)...) // signature
	return buf, nil
}

// EncodePreKeyBundle serializes a PreKeyBundleProtocol message.
func EncodePreKeyBundle(identity *Identity, preKeyID, signedPreKeyID int) ([]byte, error) {
	identityProto, err := EncodeIdentityProtocol(identity)
	if err != nil {
		return nil, err
	}

	signedPreKeyProto, err := EncodePreKeySignedProtocol(
		signedPreKeyID,
		identity.SignedPreKeys[signedPreKeyID].PublicKey(),
		identity.SigningKey,
	)
	if err != nil {
		return nil, err
	}

	var buf []byte
	buf = append(buf, pbUint32Field(0, 1)...)                    // version
	buf = append(buf, pbUint32Field(1, uint32(identity.ID))...)  // registrationId
	buf = append(buf, pbBytesField(2, identityProto)...)         // identity

	// One-time pre-key is optional. The TS server's getRandomBundle()
	// does NOT include a one-time pre-key.
	if preKeyID >= 0 && preKeyID < len(identity.PreKeys) && identity.PreKeys[preKeyID] != nil {
		preKeyProto := EncodePreKeyProtocol(preKeyID, identity.PreKeys[preKeyID].PublicKey())
		buf = append(buf, pbBytesField(3, preKeyProto)...) // preKey (optional)
	}

	buf = append(buf, pbBytesField(4, signedPreKeyProto)...)     // preKeySigned

	return buf, nil
}

// ─── Message Protocol Encoding ───────────────────────────────────────────────

// EncodeMessageProtocol serializes a MessageProtocol.
func EncodeMessageProtocol(senderRatchetKey *ecdh.PublicKey, counter, prevCounter int, ciphertext []byte) []byte {
	xy := pubKeyToXY(senderRatchetKey.Bytes())
	var buf []byte
	buf = append(buf, pbUint32Field(0, 1)...)                     // version
	buf = append(buf, pbBytesField(1, xy)...)                     // senderRatchetKey
	buf = append(buf, pbUint32Field(2, uint32(counter))...)       // counter
	buf = append(buf, pbUint32Field(3, uint32(prevCounter))...)   // previousCounter
	buf = append(buf, pbBytesField(4, ciphertext)...)             // cipherText
	return buf
}

// EncodeMessageSignedProtocol serializes a MessageSignedProtocol.
//
// Protobuf schema (from 2key-ratchet v1.0.18):
//   field 1: senderKey (ECDSAPublicKeyConverter, X||Y 64 bytes)
//   field 2: message (nested MessageProtocol)
//   field 3: signature (HMAC bytes)
//
// Note: receiverKey is NOT a protobuf field. It's set programmatically
// in the TS code but never serialized to the wire.
//
// HMAC signed data = receiverKeyXY || senderKeyXY || messageProtoBytes
// (receiverKey and senderKey are from session state, not from the wire)
func EncodeMessageSignedProtocol(
	senderSigningPubXY []byte,   // our signing key (goes to field 1)
	receiverSigningPubXY []byte, // their signing key (used in HMAC only, not serialized)
	messageProto []byte,
	hmacKey []byte,
) ([]byte, error) {
	// Compute HMAC: receiverKeyXY || senderKeyXY || messageProtoBytes
	// The ordering matches getSignedRaw() in the TS:
	//   combine(this.receiverKey.serialize(), this.senderKey.serialize(), message)
	signedData := make([]byte, 0, len(receiverSigningPubXY)+len(senderSigningPubXY)+len(messageProto))
	signedData = append(signedData, receiverSigningPubXY...)
	signedData = append(signedData, senderSigningPubXY...)
	signedData = append(signedData, messageProto...)

	sig := hmacSHA256(hmacKey, signedData)

	var buf []byte
	buf = append(buf, pbUint32Field(0, 1)...)                  // version (BaseProtocol field 0)
	buf = append(buf, pbBytesField(1, senderSigningPubXY)...)  // senderKey (field 1)
	buf = append(buf, pbBytesField(2, messageProto)...)         // message (field 2, nested)
	buf = append(buf, pbBytesField(3, sig)...)                  // signature (field 3)
	return buf, nil
}

// ─── Message Protocol Decoding ───────────────────────────────────────────────

// ParsedPreKeyMessage holds the decoded fields from a PreKeyMessageProtocol.
type ParsedPreKeyMessage struct {
	Version        uint32
	RegistrationID uint32
	PreKeyID       uint32
	PreKeySignedID uint32
	BaseKeyXY      []byte // X||Y, 64 bytes
	Identity       *ParsedIdentity
	SignedMessage   *ParsedMessageSigned
}

// ParsedIdentity holds the decoded fields of an IdentityProtocol message.
type ParsedIdentity struct {
	SigningKeyXY  []byte // X||Y, 64 bytes
	ExchangeKeyXY []byte // X||Y, 64 bytes
	Signature     []byte
	CreatedAt     string
}

// ParsedMessageSigned holds a decoded MessageSignedProtocol.
// MessageRaw preserves the original bytes of the nested MessageProtocol
// for HMAC verification (MAC-then-decrypt requires the raw wire bytes).
type ParsedMessageSigned struct {
	SenderKeyXY   []byte // X||Y, 64 bytes — protobuf field 1 (senderKey in TS schema)
	Message       *ParsedMessage
	MessageRaw    []byte // raw protobuf bytes of the nested MessageProtocol, for HMAC verification
	Signature     []byte
}

// ParsedMessage holds the decoded fields of a MessageProtocol.
type ParsedMessage struct {
	SenderRatchetKeyXY []byte // X||Y, 64 bytes
	Counter            uint32
	PreviousCounter    uint32
	CipherText         []byte
}

// DecodePreKeyMessage parses a PreKeyMessageProtocol from wire format.
func DecodePreKeyMessage(data []byte) (*ParsedPreKeyMessage, error) {
	fields, err := pbParseAll(data)
	if err != nil {
		return nil, err
	}

	msg := &ParsedPreKeyMessage{}

	for _, f := range fields {
		switch f.fieldNum {
		case 0:
			msg.Version = uint32(f.varint)
		case 1:
			msg.RegistrationID = uint32(f.varint)
		case 2:
			msg.PreKeyID = uint32(f.varint)
		case 3:
			msg.PreKeySignedID = uint32(f.varint)
		case 4:
			msg.BaseKeyXY = f.bytes
		case 5:
			id, err := decodeIdentity(f.bytes)
			if err != nil {
				return nil, fmt.Errorf("parse identity: %w", err)
			}
			msg.Identity = id
		case 6:
			sm, err := decodeMessageSigned(f.bytes)
			if err != nil {
				return nil, fmt.Errorf("parse signed message: %w", err)
			}
			msg.SignedMessage = sm
		}
	}

	return msg, nil
}

// DecodeMessageSigned parses a MessageSignedProtocol.
func DecodeMessageSigned(data []byte) (*ParsedMessageSigned, error) {
	return decodeMessageSigned(data)
}

func decodeIdentity(data []byte) (*ParsedIdentity, error) {
	fields, err := pbParseAll(data)
	if err != nil {
		return nil, err
	}
	id := &ParsedIdentity{}
	for _, f := range fields {
		switch f.fieldNum {
		case 1:
			id.SigningKeyXY = f.bytes
		case 2:
			id.ExchangeKeyXY = f.bytes
		case 3:
			id.Signature = f.bytes
		case 4:
			id.CreatedAt = string(f.bytes)
		}
	}
	return id, nil
}

func decodeMessageSigned(data []byte) (*ParsedMessageSigned, error) {
	fields, err := pbParseAll(data)
	if err != nil {
		return nil, err
	}
	sm := &ParsedMessageSigned{}
	for _, f := range fields {
		switch f.fieldNum {
		case 1:
			sm.SenderKeyXY = f.bytes
		case 2:
			sm.MessageRaw = f.bytes // preserve raw bytes for HMAC verification
			m, err := decodeMessage(f.bytes)
			if err != nil {
				return nil, err
			}
			sm.Message = m
		case 3:
			sm.Signature = f.bytes
		}
	}
	return sm, nil
}

func decodeMessage(data []byte) (*ParsedMessage, error) {
	fields, err := pbParseAll(data)
	if err != nil {
		return nil, err
	}
	m := &ParsedMessage{}
	for _, f := range fields {
		switch f.fieldNum {
		case 1:
			m.SenderRatchetKeyXY = f.bytes
		case 2:
			m.Counter = uint32(f.varint)
		case 3:
			m.PreviousCounter = uint32(f.varint)
		case 4:
			m.CipherText = f.bytes
		}
	}
	return m, nil
}

// ParsedPreKeyBundle holds a decoded PreKeyBundleProtocol.
type ParsedPreKeyBundle struct {
	Version        uint32
	RegistrationID uint32
	Identity       *ParsedIdentity
	PreKey         *ParsedPreKey
	PreKeySigned   *ParsedPreKeySigned
}

// ParsedPreKey holds a decoded PreKeyProtocol (unsigned one-time pre-key).
type ParsedPreKey struct {
	ID   uint32
	KeyXY []byte // X||Y, 64 bytes
}

// ParsedPreKeySigned holds a decoded PreKeySignedProtocol (signed pre-key with signature).
type ParsedPreKeySigned struct {
	ID        uint32
	KeyXY     []byte // X||Y, 64 bytes
	Signature []byte
}

// DecodePreKeyBundle parses a PreKeyBundleProtocol from wire format.
func DecodePreKeyBundle(data []byte) (*ParsedPreKeyBundle, error) {
	fields, err := pbParseAll(data)
	if err != nil {
		return nil, err
	}

	b := &ParsedPreKeyBundle{}
	for _, f := range fields {
		switch f.fieldNum {
		case 0:
			b.Version = uint32(f.varint)
		case 1:
			b.RegistrationID = uint32(f.varint)
		case 2:
			id, err := decodeIdentity(f.bytes)
			if err != nil {
				return nil, err
			}
			b.Identity = id
		case 3:
			pk, err := decodePreKey(f.bytes)
			if err != nil {
				return nil, err
			}
			b.PreKey = pk
		case 4:
			spk, err := decodePreKeySigned(f.bytes)
			if err != nil {
				return nil, err
			}
			b.PreKeySigned = spk
		}
	}
	return b, nil
}

func decodePreKey(data []byte) (*ParsedPreKey, error) {
	fields, err := pbParseAll(data)
	if err != nil {
		return nil, err
	}
	pk := &ParsedPreKey{}
	for _, f := range fields {
		switch f.fieldNum {
		case 1:
			pk.ID = uint32(f.varint)
		case 2:
			pk.KeyXY = f.bytes
		}
	}
	return pk, nil
}

func decodePreKeySigned(data []byte) (*ParsedPreKeySigned, error) {
	fields, err := pbParseAll(data)
	if err != nil {
		return nil, err
	}
	spk := &ParsedPreKeySigned{}
	for _, f := range fields {
		switch f.fieldNum {
		case 1:
			spk.ID = uint32(f.varint)
		case 2:
			spk.KeyXY = f.bytes
		case 3:
			spk.Signature = f.bytes
		}
	}
	return spk, nil
}

// ─── Protobuf Parser ─────────────────────────────────────────────────────────

type pbFieldVal struct {
	fieldNum int
	wireType int
	varint   uint64
	bytes    []byte
}

func pbParseAll(data []byte) ([]pbFieldVal, error) {
	var fields []pbFieldVal
	pos := 0

	for pos < len(data) {
		tag, n := binary.Uvarint(data[pos:])
		if n <= 0 {
			return nil, fmt.Errorf("invalid tag at pos %d", pos)
		}
		pos += n

		fieldNum := int(tag >> 3)
		wireType := int(tag & 0x7)

		f := pbFieldVal{fieldNum: fieldNum, wireType: wireType}

		switch wireType {
		case 0: // varint
			val, n := binary.Uvarint(data[pos:])
			if n <= 0 {
				return nil, fmt.Errorf("invalid varint at pos %d", pos)
			}
			pos += n
			f.varint = val
		case 1: // 64-bit
			if pos+8 > len(data) {
				return nil, fmt.Errorf("truncated 64-bit at pos %d", pos)
			}
			pos += 8
		case 2: // length-delimited
			length, n := binary.Uvarint(data[pos:])
			if n <= 0 {
				return nil, fmt.Errorf("invalid length at pos %d", pos)
			}
			pos += n
			if length > uint64(len(data)) || pos+int(length) > len(data) {
				return nil, fmt.Errorf("truncated bytes at pos %d, need %d, have %d", pos, length, len(data)-pos)
			}
			f.bytes = make([]byte, length)
			copy(f.bytes, data[pos:pos+int(length)])
			pos += int(length)
		case 5: // 32-bit
			if pos+4 > len(data) {
				return nil, fmt.Errorf("truncated 32-bit at pos %d", pos)
			}
			pos += 4
		default:
			return nil, fmt.Errorf("unknown wire type %d at pos %d", wireType, pos)
		}

		fields = append(fields, f)
	}

	return fields, nil
}

// ─── ECDSA Verification ──────────────────────────────────────────────────────

// VerifyIdentitySignature verifies that the identity's exchange key was
// signed by the signing key. Matches IdentityProtocol.verify() in TS.
//
// IMPORTANT: 2key-ratchet uses ECDSA with SHA-512 for Curve.sign/verify
// (Curve.DIGEST_ALGORITHM = "SHA-512"), NOT SHA-256. SHA-256 is only used
// for HMAC operations. This is an unusual choice for P-256 but it's what
// the protocol specifies.
//
// WebCrypto ECDSA uses IEEE P1363 signature format (r||s, 64 bytes for P-256).
// Go's ecdsa package uses ASN.1 DER format. We convert between them.
func VerifyIdentitySignature(signingKeyXY, exchangeKeyXY, signature []byte) bool {
	pubKey := xyToECDSAPublicKey(signingKeyXY)
	if pubKey == nil {
		return false
	}
	derSig := p1363ToDER(signature)
	if derSig == nil {
		return false
	}
	hash := sha512.Sum512(exchangeKeyXY)
	return ecdsa.VerifyASN1(pubKey, hash[:], derSig)
}

// VerifyPreKeySignature verifies a signed pre-key. Matches PreKeySignedProtocol.verify().
func VerifyPreKeySignature(signingKeyXY, preKeyXY, signature []byte) bool {
	pubKey := xyToECDSAPublicKey(signingKeyXY)
	if pubKey == nil {
		return false
	}
	derSig := p1363ToDER(signature)
	if derSig == nil {
		return false
	}
	hash := sha512.Sum512(preKeyXY)
	return ecdsa.VerifyASN1(pubKey, hash[:], derSig)
}

func xyToECDSAPublicKey(xy []byte) *ecdsa.PublicKey {
	if len(xy) != 64 {
		return nil
	}
	x := new(big.Int).SetBytes(xy[:32])
	y := new(big.Int).SetBytes(xy[32:])
	return &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     x,
		Y:     y,
	}
}

// p1363ToDER converts an IEEE P1363 ECDSA signature (r||s, fixed-length)
// to ASN.1 DER format used by Go's ecdsa package.
func p1363ToDER(p1363 []byte) []byte {
	if len(p1363) != 64 { // P-256: 32+32
		return nil
	}
	r := new(big.Int).SetBytes(p1363[:32])
	s := new(big.Int).SetBytes(p1363[32:])

	// ASN.1 DER: SEQUENCE { INTEGER r, INTEGER s }
	rBytes := r.Bytes()
	sBytes := s.Bytes()

	// Add leading zero if high bit is set (ASN.1 integer sign)
	if len(rBytes) > 0 && rBytes[0]&0x80 != 0 {
		rBytes = append([]byte{0}, rBytes...)
	}
	if len(sBytes) > 0 && sBytes[0]&0x80 != 0 {
		sBytes = append([]byte{0}, sBytes...)
	}

	// INTEGER tag + length + value for r and s
	rTLV := append([]byte{0x02, byte(len(rBytes))}, rBytes...)
	sTLV := append([]byte{0x02, byte(len(sBytes))}, sBytes...)

	// SEQUENCE tag + length + r + s
	inner := append(rTLV, sTLV...)
	return append([]byte{0x30, byte(len(inner))}, inner...)
}

// derToP1363 converts an ASN.1 DER ECDSA signature to IEEE P1363 format.
// Used when signing in Go and sending to TS clients.
func derToP1363(der []byte) []byte {
	// Parse SEQUENCE
	if len(der) < 2 || der[0] != 0x30 {
		return nil
	}
	// Parse r
	pos := 2
	if der[pos] != 0x02 {
		return nil
	}
	rLen := int(der[pos+1])
	pos += 2
	rBytes := der[pos : pos+rLen]
	pos += rLen

	// Parse s
	if der[pos] != 0x02 {
		return nil
	}
	sLen := int(der[pos+1])
	pos += 2
	sBytes := der[pos : pos+sLen]

	// Pad/trim to exactly 32 bytes each
	out := make([]byte, 64)
	r := new(big.Int).SetBytes(rBytes)
	s := new(big.Int).SetBytes(sBytes)
	rFixed := r.Bytes()
	sFixed := s.Bytes()
	copy(out[32-len(rFixed):32], rFixed)
	copy(out[64-len(sFixed):64], sFixed)
	return out
}

// VerifyMessageSignature verifies the HMAC on a MessageSignedProtocol.
// The signed data is: receiverKeyXY || senderKeyXY || messageProtoBytes
// BUT senderKey is NOT in the protobuf — it's set programmatically.
// For the receiver, senderKey = remote identity signing key XY.
func VerifyMessageHMAC(receiverKeyXY, senderKeyXY, messageProtoBytes, hmacKeyBytes, signatureBytes []byte) bool {
	signedData := make([]byte, 0, len(receiverKeyXY)+len(senderKeyXY)+len(messageProtoBytes))
	signedData = append(signedData, receiverKeyXY...)
	signedData = append(signedData, senderKeyXY...)
	signedData = append(signedData, messageProtoBytes...)

	expected := hmacSHA256(hmacKeyBytes, signedData)

	return cryptosubtle.ConstantTimeCompare(expected, signatureBytes) == 1
}
