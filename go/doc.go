// Package ratchet implements the Double Ratchet protocol used by webcrypto-socket
// for end-to-end encrypted sessions between browser clients and the local server.
//
// Go implementation of the 2key-ratchet Double Ratchet + X3DH protocol.
// The protocol follows the Signal Double Ratchet and X3DH specifications.
//
// All crypto primitives are from Go's standard library and x/crypto:
//   - ECDH with P-256 (key agreement)
//   - ECDSA with P-256 (identity signing)
//   - AES-256-CBC (message encryption, matching WebCrypto AES-CBC)
//   - HMAC-SHA-256 (chain key derivation, message authentication)
//   - HKDF-SHA-256 (root key derivation via golang.org/x/crypto/hkdf)
//
// Validated against 2key-ratchet v1.0.18 test vectors.
package ratchet


import "errors"

var (
	ErrSessionNotFound    = errors.New("ratchet: session not found")
	ErrIdentityNotTrusted = errors.New("ratchet: remote identity not trusted")
	ErrInvalidSignature   = errors.New("ratchet: invalid signature")
	ErrDecryptionFailed   = errors.New("ratchet: decryption failed")
	ErrBadPadding         = errors.New("ratchet: invalid PKCS7 padding")
	ErrMessageTooOld      = errors.New("ratchet: message counter too old")
	ErrDuplicateMessage   = errors.New("ratchet: duplicate message counter")
	ErrCounterTooLarge    = errors.New("ratchet: message counter exceeds max skip")
	ErrHMACVerifyFailed   = errors.New("ratchet: HMAC signature verification failed")
)

// MaxSkip is the maximum number of message keys to skip in a single chain.
// Matches MAX_RATCHET_STACK_SIZE in 2key-ratchet. Prevents DoS via
// attacker-controlled counter values forcing unbounded HMAC computation.
const MaxSkip = 1000


// Info strings match the constants in 2key-ratchet/const.ts.
var (
	infoText        = []byte("InfoText")
	infoRatchet     = []byte("InfoRatchet")
	infoMessageKeys = []byte("InfoMessageKeys")
)

// Chain KDF constants matching 2key-ratchet/sym_ratchet.ts.
var (
	cipherKeyKDFInput = []byte{0x01}
	rootKeyKDFInput   = []byte{0x02}
)

const maxRatchetStackSize = 20
