# DIFFERENCES

- We use secp256r1 with ECDSA and ECDH instead of ed25519 and x25519 because browsers do not have support for these algorithms in their WebCrypto implementations at this time. The use of these browser supported algorithms has several benefits, including:

  - Native cryptographic implementations that should be more resilient to subtle implementation issues such as side channels,
  - Ability to utilize non-exportable keys for both identity and authentication keys when used in the browser,
  - The use of Web Crypto should also provide both Increased performance and better battery life.

- The decision to use secp256r1 also meant we needed to extend the protocol to support separate keys for encryption and decryption. ed25519 is based on EC-Schnorr which is believed to not leak details about the key, the NIST EC curves do not have this property, hence the change. The change includes the newly introduced encryption key being signed by the corresponding identity key.
- Due to patent concerns we utilized uncompressed keys in the wire protocol, these uncompressed keys are larger but we believe them to be unencumbered.
- Unlike the original double ratchet protocol, 2key-ratchet uses Protobufs instead of TLV for packing messages, this simplifies parsing and makes code more readable.
