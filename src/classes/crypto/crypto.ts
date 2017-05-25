/**
 *
 * 2key-ratchet
 * Copyright (c) 2016 Peculiar Ventures, Inc
 * Based on https://whispersystems.org/docs/specifications/doubleratchet/ and
 * https://whispersystems.org/docs/specifications/x3dh/ by Open Whisper Systems
 *
 */

let cryptoPolyfill: Crypto;

if (typeof self === "undefined") {
    const WebCrypto = require("node-webcrypto-ossl");
    cryptoPolyfill = new WebCrypto();
} else {
    cryptoPolyfill = (self as any).crypto;
}

export default cryptoPolyfill;
