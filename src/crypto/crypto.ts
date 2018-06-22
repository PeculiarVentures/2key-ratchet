/**
 *
 * 2key-ratchet
 * Copyright (c) 2016 Peculiar Ventures, Inc
 * Based on https://whispersystems.org/docs/specifications/doubleratchet/ and
 * https://whispersystems.org/docs/specifications/x3dh/ by Open Whisper Systems
 *
 */

 /**
  * Crypto engine structure
  *
  * @export
  * @interface ICryptoEngine
  */
export interface ICryptoEngine {
    name: string;
    crypto: Crypto;
}

let engine: ICryptoEngine | null = null;

if (typeof self === "undefined") {
    // tslint:disable-next-line:no-var-requires
    const WebCrypto = require("node-webcrypto-ossl") as typeof Crypto;
    engine = {
        crypto: new WebCrypto(),
        name: "WebCrypto OpenSSL",
    };
} else {
    engine = {
        crypto: (self as any).crypto,
        name: "WebCrypto",
    };
}
/**
 * Sets crypto engine
 *
 * @export
 * @param {string} name     Name of engine
 * @param {Crypto} crypto   WebCrypto implementation
 */
export function setEngine(name: string, crypto: Crypto) {
    engine = {
        crypto,
        name,
    };
}

/**
 * Returns crypto engine
 * It throws exception if engine is empty.
 *
 * @export
 * @returns {ICryptoEngine}
 */
export function getEngine(): ICryptoEngine {
    if (!engine) {
        throw new Error("WebCrypto engine is empty. Use setEngine to resolve it.");
    }
    return engine;
}
