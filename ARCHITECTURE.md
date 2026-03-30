## OVERVIEW

![image](https://cloud.githubusercontent.com/assets/1619279/22614806/a6490b82-ea3c-11e6-8090-30577a03732f.png)

## DETAIL

![image](https://cloud.githubusercontent.com/assets/1619279/22615271/1e665c92-ea46-11e6-9d30-088942f7ec86.png)

## PACKAGE

![image](https://cloud.githubusercontent.com/assets/1619279/22614800/674c9df4-ea3c-11e6-9c4f-2d88327ab950.png)

## Go Implementation Mapping

The diagrams above reflect the TypeScript class hierarchy. The Go implementation in `go/` follows the same architecture with this file mapping:

| TypeScript | Go | Purpose |
|---|---|---|
| `src/crypto/` | `go/crypto.go` | AES-256-CBC, HMAC-SHA-256, PKCS7 padding |
| `src/data/identity.ts` | `go/identity.go` | Identity key pairs, thumbprint |
| `src/asym_ratchet.ts` (X3DH) | `go/x3dh.go` | X3DH key agreement, challenge PIN |
| `src/sym_ratchet.ts` | `go/chain.go` | Symmetric chain, message key derivation |
| `src/asym_ratchet.ts` (session) | `go/session.go` | Session management, encrypt/decrypt |
| `src/protocol/` | `go/wire.go` | Protobuf wire format, signature verification |
| `src/const.ts` | `go/doc.go` | Protocol constants, error types |
| (webcrypto-local) | `go/server.go` | WebSocket server, ratchet handshake |
| (webcrypto-local) | `go/actions.go` | CryptoProvider interface, action dispatch |

