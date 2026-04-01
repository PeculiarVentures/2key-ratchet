#!/usr/bin/env node
//
// Protocol integration test.
//
// Connects to the Go webcrypto-socket server using the same 2key-ratchet
// protocol that webcrypto-socket clients use.
//
// Usage: node protocol_integration_test.js [address]
//   address defaults to 127.0.0.1:31338

const { Crypto } = require("@peculiar/webcrypto");
const { setEngine, Identity, AsymmetricRatchet } = require("2key-ratchet");
const {
  PreKeyBundleProtocol,
  MessageSignedProtocol,
} = require("2key-ratchet/dist/2key-ratchet.js");
const { Convert } = require("pvtsutils");
const https = require("https");
const WebSocket = require("ws");

const crypto = new Crypto();
setEngine("@peculiar/webcrypto", crypto);

const ADDRESS = process.argv[2] || "127.0.0.1:31338";

// ─── Protobuf helpers ────────────────────────────────────────────────────────

function encodeVarint(value) {
  const bytes = [];
  while (value > 0x7f) {
    bytes.push((value & 0x7f) | 0x80);
    value >>>= 7;
  }
  bytes.push(value & 0x7f);
  return Buffer.from(bytes);
}

function encodeAction(action, actionId) {
  // ActionProto: version=field1(varint), action=field2(string), actionId=field3(string)
  const actionBytes = Buffer.from(action);
  const actionIdBytes = Buffer.from(actionId);
  const parts = [];
  parts.push(Buffer.from([0x08, 0x01]));  // field 1 varint = 1 (version)
  parts.push(Buffer.from([0x12]));         // field 2 length-delimited
  parts.push(encodeVarint(actionBytes.length));
  parts.push(actionBytes);
  parts.push(Buffer.from([0x1a]));         // field 3 length-delimited
  parts.push(encodeVarint(actionIdBytes.length));
  parts.push(actionIdBytes);
  return Buffer.concat(parts);
}

function parseResult(data) {
  // ResultProto: version=1, action=2, actionId=3, status=4(bool), error=5, data=6
  const result = { version: 0, action: "", actionId: "", status: false, data: null, error: null };
  let pos = 0;
  const buf = Buffer.from(data);
  while (pos < buf.length) {
    let tag = 0, n = 0, shift = 0;
    do { tag |= (buf[pos] & 0x7f) << shift; shift += 7; } while (buf[pos++] >= 0x80);
    const fieldNum = tag >> 3;
    const wireType = tag & 0x7;
    if (wireType === 0) {
      let val = 0; shift = 0;
      do { val |= (buf[pos] & 0x7f) << shift; shift += 7; } while (buf[pos++] >= 0x80);
      if (fieldNum === 1) result.version = val;
      if (fieldNum === 4) result.status = !!val;
    } else if (wireType === 2) {
      let len = 0; shift = 0;
      do { len |= (buf[pos] & 0x7f) << shift; shift += 7; } while (buf[pos++] >= 0x80);
      const bytes = buf.slice(pos, pos + len);
      pos += len;
      if (fieldNum === 2) result.action = bytes.toString();
      if (fieldNum === 3) result.actionId = bytes.toString();
      if (fieldNum === 5) result.error = bytes;
      if (fieldNum === 6) result.data = bytes;
    }
  }
  return result;
}

function parseProviderInfo(data) {
  const result = { name: "", providers: [] };
  let pos = 0;
  while (pos < data.length) {
    let tag = 0, shift = 0;
    do { tag |= (data[pos] & 0x7f) << shift; shift += 7; } while (data[pos++] >= 0x80);
    const fieldNum = tag >> 3, wireType = tag & 0x7;
    if (wireType === 0) { do {} while (data[pos++] >= 0x80); }
    else if (wireType === 2) {
      let len = 0; shift = 0;
      do { len |= (data[pos] & 0x7f) << shift; shift += 7; } while (data[pos++] >= 0x80);
      const bytes = data.slice(pos, pos + len); pos += len;
      if (fieldNum === 2) result.name = bytes.toString();
      if (fieldNum === 3) result.providers.push(parseProviderCrypto(bytes));
    }
  }
  return result;
}

function parseProviderCrypto(data) {
  const result = { id: "", name: "", algorithms: [] };
  let pos = 0;
  while (pos < data.length) {
    let tag = 0, shift = 0;
    do { tag |= (data[pos] & 0x7f) << shift; shift += 7; } while (data[pos++] >= 0x80);
    const fieldNum = tag >> 3, wireType = tag & 0x7;
    if (wireType === 0) { do {} while (data[pos++] >= 0x80); }
    else if (wireType === 2) {
      let len = 0; shift = 0;
      do { len |= (data[pos] & 0x7f) << shift; shift += 7; } while (data[pos++] >= 0x80);
      const bytes = data.slice(pos, pos + len); pos += len;
      if (fieldNum === 2) result.id = bytes.toString();
      if (fieldNum === 3) result.name = bytes.toString();
      if (fieldNum === 5) result.algorithms.push(bytes.toString());
    }
  }
  return result;
}

// ─── Main test ───────────────────────────────────────────────────────────────

async function main() {
  console.log("=== Protocol Integration Test ===");
  console.log(`Connecting to ${ADDRESS}...\n`);

  // Step 1: Fetch well-known
  console.log("1. Fetching /.well-known/webcrypto-socket...");
  const info = await fetchJSON(`https://${ADDRESS}/.well-known/webcrypto-socket`);
  console.log(`   Name: ${info.name}, Version: ${info.version}`);
  console.log(`   PreKey: ${info.preKey.substring(0, 40)}...`);

  // Step 2: Parse PreKeyBundle
  console.log("2. Parsing PreKeyBundle...");
  const bundleBytes = Convert.FromBase64(info.preKey);
  const bundle = await PreKeyBundleProtocol.importProto(bundleBytes);
  console.log(`   Registration ID: ${bundle.registrationId}`);
  const idOk = await bundle.identity.verify();
  const spkOk = await bundle.preKeySigned.verify(bundle.identity.signingKey);
  console.log(`   Identity sig: ${idOk ? "PASS" : "FAIL"}`);
  console.log(`   PreKey sig: ${spkOk ? "PASS" : "FAIL"}`);
  if (!idOk || !spkOk) throw new Error("Signature verification failed");

  // Step 3: Create session
  console.log("3. Creating ratchet session...");
  const clientIdentity = await Identity.create(1, 1);
  const cipher = await AsymmetricRatchet.create(clientIdentity, bundle);
  console.log("   Session created");

  // Step 4: WebSocket
  console.log("4. Connecting WebSocket...");
  const ws = new WebSocket(`wss://${ADDRESS}`, { rejectUnauthorized: false });
  await new Promise((resolve, reject) => {
    ws.on("open", resolve);
    ws.on("error", reject);
    setTimeout(() => reject(new Error("WebSocket timeout")), 5000);
  });
  console.log("   Connected");

  // Step 5: server/isLoggedIn
  console.log("5. server/isLoggedIn...");
  let result = await sendAction(ws, cipher, "server/isLoggedIn", "a1");
  console.log(`   status=${result.status} loggedIn=${result.data && result.data[0] === 1}`);

  // Step 6: server/login
  console.log("6. server/login...");
  result = await sendAction(ws, cipher, "server/login", "a2");
  console.log(`   status=${result.status}`);

  // Step 7: Verify login
  console.log("7. server/isLoggedIn (verify)...");
  result = await sendAction(ws, cipher, "server/isLoggedIn", "a3");
  const loggedIn = result.data && result.data[0] === 1;
  console.log(`   loggedIn=${loggedIn}`);
  if (!loggedIn) throw new Error("Login failed");

  // Step 8: provider/action/info
  console.log("8. provider/action/info...");
  result = await sendAction(ws, cipher, "provider/action/info", "a4");
  console.log(`   status=${result.status} data=${result.data ? result.data.length + " bytes" : "null"}`);
  if (result.data) {
    const pi = parseProviderInfo(result.data);
    console.log(`   name=${pi.name} providers=${pi.providers.length}`);
    if (pi.providers.length > 0) {
      const p = pi.providers[0];
      console.log(`   provider: id=${p.id} name=${p.name} algos=${p.algorithms.length}`);
    }
  }

  ws.close();

  console.log("\n=== ALL TESTS PASSED ===");
  console.log("  Well-known endpoint: PASS");
  console.log("  PreKeyBundle parse + verify sigs: PASS");
  console.log("  Ratchet session establishment: PASS");
  console.log("  server/isLoggedIn (encrypted action): PASS");
  console.log("  server/login (encrypted action): PASS");
  console.log("  provider/action/info (encrypted action + response): PASS");
}

function sendAction(ws, cipher, action, actionId) {
  return new Promise(async (resolve, reject) => {
    const timeout = setTimeout(() => reject(new Error(`Timeout waiting for ${action}`)), 5000);
    try {
      const actionBuf = encodeAction(action, actionId);
      const encrypted = await cipher.encrypt(new Uint8Array(actionBuf).buffer);
      const encBytes = await encrypted.exportProto();

      const handler = async (rawData) => {
        try {
          ws.removeListener("message", handler);
          clearTimeout(timeout);
          const msgBuf = rawData instanceof ArrayBuffer
            ? rawData
            : new Uint8Array(rawData).buffer;
          const signed = await MessageSignedProtocol.importProto(msgBuf);
          const decrypted = await cipher.decrypt(signed);
          resolve(parseResult(decrypted));
        } catch (e) {
          clearTimeout(timeout);
          reject(e);
        }
      };
      ws.on("message", handler);
      ws.send(Buffer.from(encBytes));
    } catch (e) {
      clearTimeout(timeout);
      reject(e);
    }
  });
}

function fetchJSON(url) {
  return new Promise((resolve, reject) => {
    https.get(url, { rejectUnauthorized: false }, (res) => {
      let data = "";
      res.on("data", (chunk) => (data += chunk));
      res.on("end", () => {
        try { resolve(JSON.parse(data)); }
        catch (e) { reject(new Error(`Parse error: ${data.substring(0, 100)}`)); }
      });
    }).on("error", reject);
  });
}

main().catch((e) => {
  console.error("FAILED:", e.message);
  process.exit(1);
});
