#!/usr/bin/env node
//
// Generates interop test vectors by running the full 2key-ratchet protocol
// and dumping every intermediate value as hex to a JSON file.
//
// The Go test reads this JSON and reproduces each step, asserting byte-level
// equality at every stage.
//
// Usage:
//   cd interop && npm install && node generate_vectors.js
//
// Outputs: vectors.json

const { Crypto } = require("@peculiar/webcrypto");
const { setEngine, Identity, AsymmetricRatchet } = require("2key-ratchet");
const {
  PreKeyBundleProtocol,
  PreKeyMessageProtocol,
  MessageSignedProtocol,
} = require("2key-ratchet/dist/2key-ratchet.js");
const { Convert, combine } = require("pvtsutils");
const fs = require("fs");
const path = require("path");

const crypto = new Crypto();
setEngine("@peculiar/webcrypto", crypto);

async function exportRaw(key) {
  return Convert.ToHex(await crypto.subtle.exportKey("raw", key));
}

async function exportJWK(key) {
  return await crypto.subtle.exportKey("jwk", key);
}

// ECPublicKey in 2key-ratchet serializes as X||Y (64 bytes), not 04||X||Y.
function pubRawToXY(hex65) {
  if (hex65.length === 130 && hex65.startsWith("04")) {
    return hex65.slice(2);
  }
  return hex65;
}

async function deriveBytes(privJWK, pubHex) {
  // pubHex is 04||X||Y (uncompressed, 65 bytes)
  const priv = await crypto.subtle.importKey(
    "jwk", privJWK,
    { name: "ECDH", namedCurve: "P-256" },
    false, ["deriveBits"]
  );
  const pub = await crypto.subtle.importKey(
    "raw", Convert.FromHex(pubHex),
    { name: "ECDH", namedCurve: "P-256" },
    true, []
  );
  const bits = await crypto.subtle.deriveBits(
    { name: "ECDH", public: pub }, priv, 256
  );
  return Convert.ToHex(bits);
}

async function main() {
  const vectors = {};

  // ─── Generate Identities ──────────────────────────────────────────
  const bob = await Identity.create(1, 1, 1, true);
  const alice = await Identity.create(2, 1, 1, true);

  vectors.bob = {
    id: bob.id,
    signingPub: await exportRaw(bob.signingKey.publicKey.key),
    signingPriv: await exportJWK(bob.signingKey.privateKey),
    exchangePub: await exportRaw(bob.exchangeKey.publicKey.key),
    exchangePriv: await exportJWK(bob.exchangeKey.privateKey),
    signedPreKeyPub: await exportRaw(bob.signedPreKeys[0].publicKey.key),
    signedPreKeyPriv: await exportJWK(bob.signedPreKeys[0].privateKey),
    oneTimePreKeyPub: await exportRaw(bob.preKeys[0].publicKey.key),
    oneTimePreKeyPriv: await exportJWK(bob.preKeys[0].privateKey),
  };

  vectors.alice = {
    id: alice.id,
    signingPub: await exportRaw(alice.signingKey.publicKey.key),
    signingPriv: await exportJWK(alice.signingKey.privateKey),
    exchangePub: await exportRaw(alice.exchangeKey.publicKey.key),
    exchangePriv: await exportJWK(alice.exchangeKey.privateKey),
  };

  // ─── Thumbprints ──────────────────────────────────────────────────
  vectors.bobSigningThumbprint = await bob.signingKey.publicKey.thumbprint();
  vectors.aliceSigningThumbprint = await alice.signingKey.publicKey.thumbprint();

  // ─── Challenge PIN ────────────────────────────────────────────────
  const combinedHex = vectors.bobSigningThumbprint + vectors.aliceSigningThumbprint;
  const combinedBytes = Convert.FromHex(combinedHex);
  const pinDigest = await crypto.subtle.digest("SHA-256", combinedBytes);
  const pinFloat = parseInt(Convert.ToHex(pinDigest), 16);
  const pinStr = pinFloat.toString();
  vectors.challengePin = pinStr.substr(2, 6);
  vectors.challengePinDigest = Convert.ToHex(pinDigest);

  // ─── PreKeyBundle ─────────────────────────────────────────────────
  const bundle = new PreKeyBundleProtocol();
  bundle.registrationId = bob.id;
  bundle.preKey.id = 0;
  bundle.preKey.key = bob.preKeys[0].publicKey;
  bundle.preKeySigned.id = 0;
  bundle.preKeySigned.key = bob.signedPreKeys[0].publicKey;
  await bundle.preKeySigned.sign(bob.signingKey.privateKey);
  await bundle.identity.fill(bob);

  const bundleRaw = await bundle.exportProto();
  vectors.preKeyBundleProto = Convert.ToHex(bundleRaw);

  // ─── Alice creates session (X3DH authenticateA) ───────────────────
  const aliceSession = await AsymmetricRatchet.create(alice, bundle, {
    exportableKeys: true,
  });

  vectors.aliceEphemeralPub = await exportRaw(
    aliceSession.currentRatchetKey.publicKey.key
  );
  vectors.aliceEphemeralPriv = await exportJWK(
    aliceSession.currentRatchetKey.privateKey
  );

  // Compute DH values manually for verification
  const dh1 = await deriveBytes(vectors.alice.exchangePriv, vectors.bob.signedPreKeyPub);
  const dh2 = await deriveBytes(vectors.aliceEphemeralPriv, vectors.bob.exchangePub);
  const dh3 = await deriveBytes(vectors.aliceEphemeralPriv, vectors.bob.signedPreKeyPub);
  const dh4 = await deriveBytes(vectors.aliceEphemeralPriv, vectors.bob.oneTimePreKeyPub);

  vectors.x3dh = { dh1, dh2, dh3, dh4 };

  // KM construction
  const FF = new Uint8Array(32).fill(0xff);
  const KM = combine(
    FF.buffer,
    Convert.FromHex(dh1),
    Convert.FromHex(dh2),
    Convert.FromHex(dh3),
    Convert.FromHex(dh4)
  );
  vectors.x3dh.km = Convert.ToHex(KM);

  // HKDF(KM, 1, zeros(32), "InfoText")
  const salt = await crypto.subtle.importKey(
    "raw", new Uint8Array(32),
    { name: "HMAC", hash: "SHA-256" },
    true, ["sign"]
  );
  const prk = await crypto.subtle.sign("HMAC", salt, KM);
  vectors.x3dh.hkdfPRK = Convert.ToHex(prk);

  const prkKey = await crypto.subtle.importKey(
    "raw", prk,
    { name: "HMAC", hash: "SHA-256" },
    true, ["sign"]
  );
  const infoText = Convert.FromBinary("InfoText");
  const rootKey = await crypto.subtle.sign(
    "HMAC", prkKey,
    combine(new ArrayBuffer(0), infoText, new Uint8Array([1]).buffer)
  );
  vectors.x3dh.rootKey = Convert.ToHex(rootKey);

  // Verify B side matches
  const dh1b = await deriveBytes(vectors.bob.signedPreKeyPriv, vectors.alice.exchangePub);
  const dh2b = await deriveBytes(vectors.bob.exchangePriv, vectors.aliceEphemeralPub);
  const dh3b = await deriveBytes(vectors.bob.signedPreKeyPriv, vectors.aliceEphemeralPub);
  const dh4b = await deriveBytes(vectors.bob.oneTimePreKeyPriv, vectors.aliceEphemeralPub);
  vectors.x3dh.dhSymmetryCheck = (dh1 === dh1b && dh2 === dh2b && dh3 === dh3b && dh4 === dh4b);

  // ─── Chain KDF test vector ────────────────────────────────────────
  const testCKHex = "aa".repeat(32);
  const testCK = await crypto.subtle.importKey(
    "raw", Convert.FromHex(testCKHex),
    { name: "HMAC", hash: "SHA-256" },
    true, ["sign"]
  );
  const cipherKey = await crypto.subtle.sign("HMAC", testCK, new Uint8Array([1]).buffer);
  const nextCK = await crypto.subtle.sign("HMAC", testCK, new Uint8Array([2]).buffer);

  vectors.chainKDF = {
    inputChainKey: testCKHex,
    cipherKey: Convert.ToHex(cipherKey),
    nextChainKey: Convert.ToHex(nextCK),
  };

  // Message key derivation
  const infoMsg = Convert.FromBinary("InfoMessageKeys");
  const msgSalt = await crypto.subtle.importKey(
    "raw", new Uint8Array(32),
    { name: "HMAC", hash: "SHA-256" },
    true, ["sign"]
  );
  const msgPRK = await crypto.subtle.sign("HMAC", msgSalt, cipherKey);
  const msgPRKKey = await crypto.subtle.importKey(
    "raw", msgPRK,
    { name: "HMAC", hash: "SHA-256" },
    true, ["sign"]
  );
  const t1 = await crypto.subtle.sign("HMAC", msgPRKKey,
    combine(new ArrayBuffer(0), infoMsg, new Uint8Array([1]).buffer));
  const t2 = await crypto.subtle.sign("HMAC", msgPRKKey,
    combine(t1, infoMsg, new Uint8Array([2]).buffer));
  const t3 = await crypto.subtle.sign("HMAC", msgPRKKey,
    combine(t2, infoMsg, new Uint8Array([3]).buffer));

  vectors.messageKeys = {
    hkdfPRK: Convert.ToHex(msgPRK),
    aesKey: Convert.ToHex(t1),
    hmacKey: Convert.ToHex(t2),
    ivMaterial: Convert.ToHex(t3),
    iv: Convert.ToHex(t3).substring(0, 32),
  };

  // ─── AES-CBC test ─────────────────────────────────────────────────
  const aesKey = await crypto.subtle.importKey(
    "raw", t1,
    { name: "AES-CBC", length: 256 },
    false, ["encrypt", "decrypt"]
  );
  const iv = new Uint8Array(Convert.FromHex(Convert.ToHex(t3).substring(0, 32)));
  const plaintext = "Hello Bob";
  const ct = await crypto.subtle.encrypt(
    { name: "AES-CBC", iv },
    aesKey,
    Convert.FromUtf8String(plaintext)
  );

  vectors.aesCBC = {
    plaintext,
    ciphertext: Convert.ToHex(ct),
  };

  // ─── Full round trip ──────────────────────────────────────────────
  const msg = Convert.FromUtf8String("Hello from Alice");
  const enc = await aliceSession.encrypt(msg);
  const encRaw = await enc.exportProto();

  vectors.roundTrip = {
    alicePlaintext: "Hello from Alice",
    aliceEncryptedProto: Convert.ToHex(encRaw),
    aliceEncryptedSize: encRaw.byteLength,
  };

  // Bob parses and decrypts
  const preKeyMsg = await PreKeyMessageProtocol.importProto(encRaw);
  const bobSession = await AsymmetricRatchet.create(bob, preKeyMsg, {
    exportableKeys: true,
  });
  const decrypted = await bobSession.decrypt(preKeyMsg.signedMessage);

  vectors.roundTrip.bobDecrypted = Convert.ToUtf8String(decrypted);
  vectors.roundTrip.success = vectors.roundTrip.bobDecrypted === "Hello from Alice";

  // Bob replies
  const reply = Convert.FromUtf8String("Hello from Bob");
  const encReply = await bobSession.encrypt(reply);
  const replyRaw = await encReply.exportProto();
  vectors.roundTrip.bobReplyProto = Convert.ToHex(replyRaw);
  vectors.roundTrip.bobReplySize = replyRaw.byteLength;

  // Alice decrypts reply
  const replyMsg = await MessageSignedProtocol.importProto(replyRaw);
  const decReply = await aliceSession.decrypt(replyMsg);
  vectors.roundTrip.aliceDecryptedReply = Convert.ToUtf8String(decReply);
  vectors.roundTrip.replySuccess =
    vectors.roundTrip.aliceDecryptedReply === "Hello from Bob";

  // ─── Negative test: tampered PreKeyBundle ─────────────────────────
  vectors.negative = {};

  // Bundle with corrupted identity signature
  const badBundleHex = vectors.preKeyBundleProto;
  // Flip one byte in the identity signature (byte at offset 10)
  const badBytes = Buffer.from(badBundleHex, "hex");
  badBytes[10] = badBytes[10] ^ 0x01;
  vectors.negative.tamperedBundleProto = badBytes.toString("hex");

  // Existing test vectors from the TS test suite
  vectors.negative.wrongIdentitySignature =
    "0001080112c80100010a407d36fdb6ca56228dc9f0f5d95c1b2208bc170689ae30591d4f3394d123ddc399e06ff32694138f2fa120856bf26bc2330c44c3281b98a43721c66a8d59f672d412406fd1dd2fb4888007747c5bb8d8c4f137c48f829c130b6f3e4121ea8a5e84d604233f6e358922296eb8a9cfd1cdf26589aaa2d26dd327c91058e09a6256859e171a409b56a6e41227737dc73def7cc4205e436050bd5dcce2059f1ca597669be70b8b70a610835d7e7048f7857d0812da1fa31c3dd7540b7192b44902cab21fdab14b1a002288010001080112401e3c3a63c6c16fc17b13206c3dffd1a88f6d878ab5e89651fc81acc8da29903b985379d4b10f0c7c7b15d7f29e6bc81aab1ce1f92a2fc5751a10ed7ee286fc041a4063f2678382893923f0f273bfc9cabb4eb1c6ce49416d7b04a2fe1f064d472b0ec3dc2a703da56e27176386c2a6ce73c09a08f588bcccc73968cf53356ad7e275";

  vectors.negative.wrongPreKeySignature =
    "0001080112c80100010a40b1dca43fa2a920dd8882a3e4d5f2f8876e32bcc62d63082e85e1b2f87074772206641f7fdd1fea216bd279cb602351e0280f999a72c54d2d40ca192875cb4fe41240cbc78e1e0af61c1966e8a604bb55fa6468f96f9b3f32e883b9d49e3d8a9f5d43284aacb0cfbecf6db6d664a504c975e870a2aa20bc3d8b07eb627862c5362b661a40fd97642ea246beb1e73e3aede401e2fb6010f799e4791524a1dd918cf84f9a2d3d1448af677a29b8fd96449577e3f3264cec06ac7b2f83a9af944a13c8d9efcf228801000108011240ab2c101850cfb9a31127f26a4fd139ba2de720b6d2043721b10a306f69fb64a5d9dba92130e9236f35cb6c66e89ec25b9662170b2f5e82528e57b08fe92ccf7a1a409814ad399b735642f36bc2f22bf297f31e48e1fd6ab2a965398188e090aaa1300419169d0ec692fa21557db58ba3701ddc5cfc74c66539cdb28f8d8dbddbc07c";

  // ─── Write vectors ────────────────────────────────────────────────
  const outPath = path.join(__dirname, "vectors.json");
  fs.writeFileSync(outPath, JSON.stringify(vectors, null, 2));
  console.log(`Wrote ${outPath} (${Object.keys(vectors).length} top-level keys)`);
  console.log("Round trip:", vectors.roundTrip.success ? "PASS" : "FAIL");
  console.log("Reply trip:", vectors.roundTrip.replySuccess ? "PASS" : "FAIL");
  console.log("DH symmetry:", vectors.x3dh.dhSymmetryCheck ? "PASS" : "FAIL");
}

main().catch((e) => {
  console.error("FAILED:", e);
  process.exit(1);
});
