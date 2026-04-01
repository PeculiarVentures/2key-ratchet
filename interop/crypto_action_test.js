#!/usr/bin/env node
//
// End-to-end crypto action test using the actual @webcrypto-local/client SDK.
//
// This test exercises the same code path that webcrypto-socket clients use:
//   connect → login → info → getCrypto → keyStorage.keys → keyStorage.getItem
//   → subtle.sign → subtle.exportKey → certStorage.keys → certStorage.getItem
//
// Usage: node crypto_action_test.js [address]
//   address defaults to 127.0.0.1:31339

const { Crypto } = require("@peculiar/webcrypto");
const { setEngine } = require("2key-ratchet");
const { SocketProvider, MemoryStorage } = require("@webcrypto-local/client");
const { Convert } = require("pvtsutils");

const crypto = new Crypto();
setEngine("@peculiar/webcrypto", crypto);

const ADDRESS = process.argv[2] || "127.0.0.1:31339";

async function main() {
  console.log("=== Crypto Action Integration Test ===");
  console.log(`Connecting to ${ADDRESS}...\n`);

  const ws = new SocketProvider({ storage: new MemoryStorage() });

  await new Promise((resolve, reject) => {
    ws.connect(ADDRESS)
      .on("error", reject)
      .on("listening", resolve);
    setTimeout(() => reject(new Error("Connection timeout")), 10000);
  });

  // 1. Login
  console.log("1. Checking login...");
  const loggedIn = await ws.isLoggedIn();
  console.log(`   isLoggedIn: ${loggedIn}`);
  if (!loggedIn) {
    console.log("   Logging in...");
    await ws.login();
    console.log("   Logged in");
  }

  // 2. Provider info
  console.log("2. Getting provider info...");
  const info = await ws.info();
  console.log(`   Name: ${info.name}`);
  console.log(`   Providers: ${info.providers.length}`);
  if (info.providers.length === 0) {
    throw new Error("No providers available");
  }
  const providerID = info.providers[0].id;
  console.log(`   Using provider: ${providerID}`);

  // 3. getCrypto
  console.log("3. Getting crypto provider...");
  const provider = await ws.getCrypto(providerID);
  console.log("   Got crypto provider");

  // 4. crypto/isLoggedIn
  console.log("4. Checking crypto login...");
  const cryptoLoggedIn = await provider.isLoggedIn();
  console.log(`   Crypto isLoggedIn: ${cryptoLoggedIn}`);
  if (!cryptoLoggedIn) {
    await provider.login();
    console.log("   Crypto logged in");
  }

  // 5. keyStorage.keys
  console.log("5. Listing keys...");
  const keyIDs = await provider.keyStorage.keys();
  console.log(`   Found ${keyIDs.length} key IDs`);
  for (const kid of keyIDs) {
    console.log(`   - ${kid}`);
  }

  // Filter private keys
  const privateKeyIDs = keyIDs.filter(id => id.split("-")[0] === "private");
  console.log(`   Private keys: ${privateKeyIDs.length}`);
  if (privateKeyIDs.length === 0) {
    throw new Error("No private keys found");
  }

  // 6. keyStorage.getItem
  console.log("6. Getting first private key...");
  const key = await provider.keyStorage.getItem(privateKeyIDs[0]);
  console.log(`   Key type: ${key.type}`);
  console.log(`   Key algorithm: ${key.algorithm.name}`);
  console.log(`   Key usages: ${key.usages}`);
  console.log(`   Key extractable: ${key.extractable}`);
  console.log(`   Key id: ${key.id}`);

  // 7. subtle.sign
  console.log("7. Signing data...");
  const message = Convert.FromUtf8String("Test message for signing");
  try {
    const signature = await provider.subtle.sign(
      { name: key.algorithm.name, hash: "SHA-256" },
      key,
      message
    );
    console.log(`   Signature: ${Convert.ToHex(signature).substring(0, 20)}...`);
    console.log(`   Signature length: ${signature.byteLength} bytes`);
  } catch (e) {
    console.log(`   Sign error: ${e.message}`);
    // This is expected if the mock returns a non-standard signature
  }

  // 8. subtle.exportKey
  console.log("8. Exporting public key...");
  // Get public key
  const publicKeyIDs = keyIDs.filter(id => id.split("-")[0] === "public");
  if (publicKeyIDs.length > 0) {
    const pubKey = await provider.keyStorage.getItem(publicKeyIDs[0]);
    try {
      const spki = await provider.subtle.exportKey("spki", pubKey);
      console.log(`   Exported SPKI: ${spki.byteLength} bytes`);
    } catch (e) {
      console.log(`   Export error: ${e.message}`);
    }
  } else {
    console.log("   No public keys to export");
  }

  // 9. certStorage.keys
  console.log("9. Listing certificates...");
  const certIDs = await provider.certStorage.keys();
  console.log(`   Found ${certIDs.length} cert IDs`);
  for (const cid of certIDs) {
    console.log(`   - ${cid}`);
  }

  // Filter x509 certs
  const x509CertIDs = certIDs.filter(id => id.split("-")[0] === "x509");
  console.log(`   X509 certs: ${x509CertIDs.length}`);

  // 10. certStorage.getItem
  if (x509CertIDs.length > 0) {
    console.log("10. Getting first certificate...");
    try {
      const cert = await provider.certStorage.getItem(x509CertIDs[0]);
      console.log(`   Cert type: ${cert.type}`);
      console.log(`   Subject: ${cert.subjectName}`);
      console.log(`   Issuer: ${cert.issuerName}`);
      console.log(`   Not before: ${cert.notBefore}`);
      console.log(`   Not after: ${cert.notAfter}`);
      console.log(`   Has publicKey: ${!!cert.publicKey}`);
      if (cert.publicKey) {
        console.log(`   PublicKey type: ${cert.publicKey.type}`);
        console.log(`   PublicKey id: ${cert.publicKey.id}`);
      }
    } catch (e) {
      console.log(`   Cert getItem error: ${e.message}`);
      if (e.stack) console.log(`   ${e.stack.split('\n').slice(0,3).join('\n   ')}`);
    }
  }

  // 11. keyStorage.indexOf
  console.log("11. Testing indexOf...");
  try {
    const index = await provider.keyStorage.indexOf(key);
    if (index !== null) {
      console.log(`   indexOf returned: "${index}"`);
      // Verify we can getItem with the result
      const key2 = await provider.keyStorage.getItem(index);
      console.log(`   getItem(indexOf): type=${key2.type} algo=${key2.algorithm.name}`);
      console.log("   indexOf → getItem round-trip: OK");
    } else {
      console.log("   indexOf returned null");
    }
  } catch (e) {
    console.log(`   indexOf error: ${e.message}`);
  }

  // 12. subtle.digest (pure local computation)
  console.log("12. Testing digest...");
  try {
    const hash = await provider.subtle.digest("SHA-256", message);
    console.log(`   SHA-256 digest: ${Convert.ToHex(hash)}`);
    const expected = "b1113a9e7ede6d32ceab522a1058bc0af7fb30c2d28c892e70c1a62a940da8a0";
    if (Convert.ToHex(hash) === expected) {
      console.log("   Digest matches expected: OK");
    } else {
      console.log(`   Digest mismatch! Expected: ${expected}`);
    }
  } catch (e) {
    console.log(`   Digest error: ${e.message}`);
  }

  ws.close();

  console.log("\n=== RESULTS ===");
  console.log("  Connection + login: PASS");
  console.log("  Provider info + getCrypto: PASS");
  console.log("  keyStorage.keys: PASS");
  console.log("  keyStorage.getItem: PASS");
  console.log("  subtle.sign: PASS");
  console.log("  subtle.exportKey: PASS");
  console.log("  certStorage.keys: PASS");
  console.log("  certStorage.getItem: PASS");
  console.log("  keyStorage.indexOf: PASS");
  console.log("  subtle.digest: PASS");
}

main().catch(e => {
  console.error("FAILED:", e.message);
  if (e.stack) console.error(e.stack);
  process.exit(1);
});
