package ratchet

// WebSocket transport for the 2key-ratchet protocol.
//
// This implements the webcrypto-socket server: a WSS endpoint that serves
// a PreKeyBundle, establishes 2key-ratchet sessions with connecting clients,
// and routes decrypted actions through the OnAction callback.
//
// This is a transport layer, not part of the core ratchet protocol.
// The protocol primitives are in ratchet.go and wire.go.

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"sync"

	"github.com/gorilla/websocket"
)

const (
	// MaxWebSocketMessageSize limits incoming WebSocket messages (64KB).
	MaxWebSocketMessageSize = 64 * 1024

	// DefaultPreKeyPoolSize is the number of signed pre-keys per identity.
	DefaultPreKeyPoolSize = 10
)

// ServerConfig configures the webcrypto-socket server.
type ServerConfig struct {
	// Address to listen on. Default: 127.0.0.1:31337
	Address string

	// TLS certificate for HTTPS/WSS.
	TLSCert tls.Certificate

	// Identity is the server's ratchet identity.
	Identity *Identity

	// ProviderName is the name reported in provider/action/info responses.
	// Default: "WebCrypto Provider"
	ProviderName string

	// ProviderID is the identifier for the default crypto provider.
	// Default: "default"
	ProviderID string

	// OnChallenge is called when a client sends server/login.
	// The PIN and origin are provided. Return true to approve.
	// If nil, all sessions are auto-approved (test mode only).
	OnChallenge func(pin string, origin string) bool

	// CryptoProvider handles webcrypto-local actions (crypto/subtle/*,
	// crypto/keyStorage/*, crypto/certificateStorage/*, provider/action/getCrypto).
	// If set, actions are parsed and dispatched through DispatchAction.
	// If nil, OnAction is used instead.
	CryptoProvider CryptoProvider

	// OnAction is called for actions not handled by built-in handlers
	// or the CryptoProvider. Returns the response payload bytes.
	OnAction func(session *ClientSession, action string, actionID string, payload []byte) ([]byte, error)

	// AllowedOrigins restricts which browser origins can connect.
	// If empty, all origins are allowed (not recommended for production).
	AllowedOrigins []string

	// Logger (optional).
	Logger *log.Logger
}

// ClientSession represents a connected webcrypto-socket client.
type ClientSession struct {
	Conn       *websocket.Conn
	Ratchet    *Session
	Origin     string
	Authorized bool
	mu         sync.Mutex
}

// WebCryptoServer implements the webcrypto-socket protocol.
type WebCryptoServer struct {
	config        ServerConfig
	upgrader      websocket.Upgrader
	bundleCache   []byte // cached PreKeyBundle protobuf bytes
	bundleCacheMu sync.RWMutex
}

// wellKnownResponse is the JSON returned by /.well-known/webcrypto-socket.
type wellKnownResponse struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	PreKey  string `json:"preKey"` // base64-encoded PreKeyBundleProtocol
}

// NewWebCryptoServer creates a new server.
func NewWebCryptoServer(config ServerConfig) (*WebCryptoServer, error) {
	if config.Address == "" {
		config.Address = "127.0.0.1:31337"
	}
	if config.ProviderName == "" {
		config.ProviderName = "WebCrypto Provider"
	}
	if config.ProviderID == "" {
		config.ProviderID = "default"
	}
	if config.Identity == nil {
		id, err := GenerateIdentity(1, DefaultPreKeyPoolSize, 0)
		if err != nil {
			return nil, err
		}
		config.Identity = id
	}

	srv := &WebCryptoServer{
		config: config,
		upgrader: websocket.Upgrader{
			CheckOrigin: func(r *http.Request) bool {
				return config.isOriginAllowed(r.Header.Get("Origin"))
			},
		},
	}

	if config.OnChallenge == nil {
		srv.log("WARNING: OnChallenge is nil, all sessions will be auto-approved without PIN verification")
	}
	if len(config.AllowedOrigins) == 0 {
		srv.log("WARNING: AllowedOrigins is empty, all origins will be accepted")
	}

	// Pre-generate the bundle. Use signed pre-key 0.
	// The TS server picks a random signed pre-key per request;
	// we cache one for simplicity. No one-time pre-key is included,
	// matching the TS server getRandomBundle() behavior.
	bundleBytes, err := EncodePreKeyBundle(config.Identity, -1, 0)
	if err != nil {
		return nil, fmt.Errorf("encode PreKeyBundle: %w", err)
	}
	srv.bundleCache = bundleBytes

	return srv, nil
}

func (c *ServerConfig) isOriginAllowed(origin string) bool {
	if len(c.AllowedOrigins) == 0 {
		return true
	}
	for _, allowed := range c.AllowedOrigins {
		if origin == allowed {
			return true
		}
	}
	return false
}

// ListenAndServe starts the server. Blocks until ctx is canceled.
func (s *WebCryptoServer) ListenAndServe(ctx context.Context) error {
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/webcrypto-socket", s.handleWellKnown)
	mux.HandleFunc("/", s.handleWebSocket)

	server := &http.Server{
		Handler: mux,
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{s.config.TLSCert},
			MinVersion:   tls.VersionTLS12,
		},
	}

	ln, err := net.Listen("tcp", s.config.Address)
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}
	tlsLn := tls.NewListener(ln, server.TLSConfig)

	s.log("Server listening on wss://%s", s.config.Address)

	go func() {
		<-ctx.Done()
		server.Close()
	}()

	if err := server.Serve(tlsLn); err != http.ErrServerClosed {
		return err
	}
	return nil
}

func (s *WebCryptoServer) handleWellKnown(w http.ResponseWriter, r *http.Request) {
	s.bundleCacheMu.RLock()
	bundleBytes := s.bundleCache
	s.bundleCacheMu.RUnlock()

	resp := wellKnownResponse{
		Name:    s.config.ProviderName,
		Version: "1.2.0",
		PreKey:  base64.StdEncoding.EncodeToString(bundleBytes),
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	json.NewEncoder(w).Encode(resp)

	s.log("Served PreKeyBundle (%d bytes) to %s", len(bundleBytes), r.RemoteAddr)
}

func (s *WebCryptoServer) handleWebSocket(w http.ResponseWriter, r *http.Request) {
	conn, err := s.upgrader.Upgrade(w, r, nil)
	if err != nil {
		s.log("WebSocket upgrade: %v", err)
		return
	}
	defer conn.Close()

	conn.SetReadLimit(MaxWebSocketMessageSize)

	cs := &ClientSession{
		Conn:   conn,
		Origin: r.Header.Get("Origin"),
	}

	s.log("Client connected from %s (origin: %s)", conn.RemoteAddr(), cs.Origin)

	for {
		msgType, data, err := conn.ReadMessage()
		if err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseNormalClosure) {
				s.log("Read error: %v", err)
			}
			return
		}
		if msgType != websocket.BinaryMessage {
			continue
		}

		s.handleMessage(cs, data)
	}
}

func (s *WebCryptoServer) handleMessage(cs *ClientSession, data []byte) {
	if cs.Ratchet == nil {
		s.handleFirstMessage(cs, data)
		return
	}

	sm, err := DecodeMessageSigned(data)
	if err != nil {
		s.log("Decode MessageSigned: %v", err)
		return
	}

	plaintext, err := cs.Ratchet.DecryptSignedMessage(sm)
	if err != nil {
		s.log("Decrypt: %v", err)
		return
	}

	s.handleDecryptedAction(cs, plaintext)
}

func (s *WebCryptoServer) handleFirstMessage(cs *ClientSession, data []byte) {
	preKeyMsg, err := DecodePreKeyMessage(data)
	if err != nil {
		s.log("Decode PreKeyMessage: %v", err)
		return
	}

	verified, err := VerifyAndCreatePreKeyMessage(preKeyMsg)
	if err != nil {
		s.log("Verify PreKeyMessage: %v", err)
		return
	}

	session, err := CreateSessionResponder(s.config.Identity, verified)
	if err != nil {
		s.log("CreateSessionResponder: %v", err)
		return
	}

	cs.Ratchet = session
	s.log("Session established (registration=%d preKey=%d spk=%d)",
		verified.RegistrationID, verified.PreKeyID, verified.SignedPreKeyID)

	if preKeyMsg.SignedMessage != nil {
		plaintext, err := cs.Ratchet.DecryptSignedMessage(preKeyMsg.SignedMessage)
		if err != nil {
			s.log("Decrypt first message: %v", err)
			return
		}
		s.handleDecryptedAction(cs, plaintext)
	}
}

func (s *WebCryptoServer) handleDecryptedAction(cs *ClientSession, plaintext []byte) {
	// Parse ActionProto: version=field1, action=field2, actionId=field3
	fields, err := pbParseAll(plaintext)
	if err != nil {
		s.log("Parse action: %v", err)
		return
	}

	var action, actionID string
	for _, f := range fields {
		switch f.fieldNum {
		case 2:
			action = string(f.bytes)
		case 3:
			actionID = string(f.bytes)
		}
	}

	s.log("Action: %s (id=%s)", action, actionID)

	// server/isLoggedIn and server/login are allowed without authorization
	// (matching the TS server behavior). All other actions require
	// an authorized session.
	switch action {
	case "server/isLoggedIn":
		var data []byte
		if cs.Authorized {
			data = []byte{1}
		} else {
			data = []byte{0}
		}
		s.sendResult(cs, actionID, action, data)
		return

	case "server/login":
		s.handleLogin(cs, actionID, action)
		return
	}

	// All other actions require authorization
	if !cs.Authorized {
		s.log("Unauthorized action: %s (origin: %s)", action, cs.Origin)
		s.sendErrorResult(cs, actionID, action, "Unauthorized")
		return
	}

	var responseData []byte

	switch action {
	case "provider/action/info":
		responseData = s.buildProviderInfo()

	default:
		if s.config.CryptoProvider != nil {
			responseData, err = DispatchAction(s.config.CryptoProvider, action, plaintext)
			if err != nil {
				s.log("CryptoProvider error: %s: %v", action, err)
				s.sendErrorResult(cs, actionID, action, err.Error())
				return
			}
		} else if s.config.OnAction != nil {
			responseData, err = s.config.OnAction(cs, action, actionID, plaintext)
			if err != nil {
				s.log("Action handler error: %v", err)
				s.sendErrorResult(cs, actionID, action, err.Error())
				return
			}
		} else {
			s.log("Unhandled action: %s", action)
			s.sendErrorResult(cs, actionID, action, "not implemented")
			return
		}
	}

	s.sendResult(cs, actionID, action, responseData)
}

// handleLogin implements the challenge PIN flow matching the TS server:
//  1. Compute challenge PIN from server + client signing keys
//  2. Call OnChallenge callback with PIN and origin
//  3. Authorize only if callback returns true
//  4. If no callback, auto-approve (test mode)
func (s *WebCryptoServer) handleLogin(cs *ClientSession, actionID, action string) {
	if cs.Authorized {
		// Already authorized, no-op
		s.sendResult(cs, actionID, action, nil)
		return
	}

	if cs.Ratchet == nil {
		s.sendErrorResult(cs, actionID, action, "session not initialized")
		return
	}

	if s.config.OnChallenge != nil {
		// Compute challenge PIN
		pin := ComputeChallenge(
			cs.Ratchet.LocalSigningKeyXY,
			cs.Ratchet.RemoteSigningKeyXY,
		)

		s.log("Challenge PIN: %s (origin: %s)", pin, cs.Origin)

		approved := s.config.OnChallenge(pin, cs.Origin)
		if !approved {
			s.log("Session rejected by user (origin: %s)", cs.Origin)
			s.sendErrorResult(cs, actionID, action, "RATCHET_KEY_NOT_APPROVED")
			return
		}
	}

	cs.Authorized = true
	s.log("Session authorized (origin: %s)", cs.Origin)
	s.sendResult(cs, actionID, action, nil)
}

func (s *WebCryptoServer) buildProviderInfo() []byte {
	algorithms := []string{
		"RSASSA-PKCS1-v1_5", "RSA-PSS", "RSA-OAEP",
		"ECDSA", "ECDH", "AES-CBC", "AES-GCM",
		"SHA-1", "SHA-256", "SHA-384", "SHA-512",
	}

	// ProviderCryptoProto: version=1, id=2, name=3, readOnly=4,
	// algorithms=5(repeated), isRemovable=6, atr=7, isHardware=8
	var provBuf []byte
	provBuf = append(provBuf, pbUint32Field(1, 1)...)
	provBuf = append(provBuf, pbBytesField(2, []byte(s.config.ProviderID))...)
	provBuf = append(provBuf, pbBytesField(3, []byte(s.config.ProviderName))...)
	provBuf = append(provBuf, pbUint32Field(4, 0)...)
	for _, a := range algorithms {
		provBuf = append(provBuf, pbBytesField(5, []byte(a))...)
	}
	provBuf = append(provBuf, pbUint32Field(6, 0)...)
	provBuf = append(provBuf, pbUint32Field(8, 0)...)

	// ProviderInfoProto: version=1, name=2, providers=3(repeated)
	var infoBuf []byte
	infoBuf = append(infoBuf, pbUint32Field(1, 1)...)
	infoBuf = append(infoBuf, pbBytesField(2, []byte(s.config.ProviderName))...)
	infoBuf = append(infoBuf, pbBytesField(3, provBuf)...)

	return infoBuf
}

func (s *WebCryptoServer) sendResult(cs *ClientSession, actionID, action string, data []byte) {
	// ResultProto: version=1, action=2, actionId=3, status=4, error=5, data=6
	var buf []byte
	buf = append(buf, pbUint32Field(1, 1)...)
	buf = append(buf, pbBytesField(2, []byte(action))...)
	buf = append(buf, pbBytesField(3, []byte(actionID))...)
	buf = append(buf, pbUint32Field(4, 1)...)
	if data != nil {
		buf = append(buf, pbBytesField(6, data)...)
	}

	s.sendEncrypted(cs, buf)
}

func (s *WebCryptoServer) sendErrorResult(cs *ClientSession, actionID, action, message string) {
	// ErrorProto: version=1, code=2, type=3, message=4, name=5, stack=6
	var errBuf []byte
	errBuf = append(errBuf, pbUint32Field(1, 1)...)
	errBuf = append(errBuf, pbUint32Field(2, 500)...)
	errBuf = append(errBuf, pbBytesField(3, []byte("error"))...)
	errBuf = append(errBuf, pbBytesField(4, []byte(message))...)
	errBuf = append(errBuf, pbBytesField(5, []byte("Error"))...)

	var buf []byte
	buf = append(buf, pbUint32Field(1, 1)...)
	buf = append(buf, pbBytesField(2, []byte(action))...)
	buf = append(buf, pbBytesField(3, []byte(actionID))...)
	buf = append(buf, pbUint32Field(4, 0)...)
	buf = append(buf, pbBytesField(5, errBuf)...)

	s.sendEncrypted(cs, buf)
}

func (s *WebCryptoServer) sendEncrypted(cs *ClientSession, plaintext []byte) {
	cs.mu.Lock()
	defer cs.mu.Unlock()

	if cs.Ratchet == nil {
		s.log("Cannot send: no ratchet session")
		return
	}

	ct, hmacKey, counter, err := cs.Ratchet.EncryptMessage(plaintext)
	if err != nil {
		s.log("Encrypt: %v", err)
		return
	}

	ratchetKeyPub := cs.Ratchet.RatchetKey.PublicKey()
	msgProto := EncodeMessageProtocol(ratchetKeyPub, counter, cs.Ratchet.Counter, ct)

	// senderKey (field 1) = our signing key (we are the sender)
	// receiverKey (HMAC only) = client's signing key
	signedProto, err := EncodeMessageSignedProtocol(
		cs.Ratchet.LocalSigningKeyXY,
		cs.Ratchet.RemoteSigningKeyXY,
		msgProto,
		hmacKey,
	)
	if err != nil {
		s.log("Encode signed message: %v", err)
		return
	}

	if err := cs.Conn.WriteMessage(websocket.BinaryMessage, signedProto); err != nil {
		s.log("Write: %v", err)
	}
}

func (s *WebCryptoServer) log(format string, args ...interface{}) {
	if s.config.Logger != nil {
		s.config.Logger.Printf(format, args...)
	} else {
		log.Printf("[webcrypto-server] "+format, args...)
	}
}

// GenerateSelfSignedCert generates a self-signed TLS certificate for 127.0.0.1.
func GenerateSelfSignedCert() (tls.Certificate, error) {
	return generateSelfSignedTLSCert()
}
