/**
 * 
 * 2key-ratchet
 * Copyright (c) 2016 Peculiar Ventures, Inc
 * Based on https://whispersystems.org/docs/specifications/doubleratchet/ and 
 * https://whispersystems.org/docs/specifications/x3dh/ by Open Whisper Systems
 * 
 */

import { HASH_NAME, HMAC_NAME, SECRET_KEY_NAME } from "../const";
import { HMACCryptoKey } from "../type";
import { combine, Convert } from "../utils";
import crypto from "./crypto";

const AES_ALGORITHM = { name: "AES-CBC", length: 256 };

export class Secret {

    public static subtle = crypto.subtle;

    /**
     * Returns ArrayBuffer of random bytes
     * 
     * @static
     * @param {number} size size of output buffer
     * @returns
     * 
     * @memberOf Secret
     */
    public static randomBytes(size: number) {
        const array = new Uint8Array(size);
        crypto.getRandomValues(array);
        return array.buffer;
    }

    /**
     * Calculates digest
     * 
     * @static
     * @param {string} alg
     * @param {ArrayBuffer} message
     * @returns
     * 
     * @memberOf Secret
     */
    public static digest(alg: string, message: ArrayBuffer) {
        return crypto.subtle.digest(alg, message);
    }

    /**
     * Encrypts data
     * 
     * @static
     * @param {CryptoKey} key
     * @param {ArrayBuffer} data
     * @param {ArrayBuffer} iv
     * @returns
     * 
     * @memberOf Secret
     */
    public static encrypt(key: CryptoKey, data: ArrayBuffer, iv: ArrayBuffer) {
        return crypto.subtle.encrypt({ name: SECRET_KEY_NAME, iv: new Uint8Array(iv) }, key, data);
    }

    /**
     * Decrypts data
     * 
     * @static
     * @param {CryptoKey} key
     * @param {ArrayBuffer} data
     * @param {ArrayBuffer} iv
     * @returns
     * 
     * @memberOf Secret
     */
    public static decrypt(key: CryptoKey, data: ArrayBuffer, iv: ArrayBuffer) {
        return crypto.subtle.decrypt({ name: SECRET_KEY_NAME, iv: new Uint8Array(iv) }, key, data);
    }

    /**
     * Creates HMAC key from raw data
     * 
     * @static
     * @param {ArrayBuffer} raw
     * @returns
     * 
     * @memberOf Secret
     */
    public static importHMAC(raw: ArrayBuffer) {
        // console.log("Import HMAC:", new Buffer(raw).toString("hex"));
        return crypto.subtle
            .importKey("raw", raw, { name: HMAC_NAME, hash: { name: HASH_NAME } }, false, ["sign", "verify"]);
    }

    /**
     * Creates AES key from raw data
     * 
     * @static
     * @param {ArrayBuffer} raw
     * @returns
     * 
     * @memberOf Secret
     */
    public static importAES(raw: ArrayBuffer) {
        // console.log("Import AES:", new Buffer(raw).toString("hex"));
        return crypto.subtle.importKey("raw", raw, AES_ALGORITHM, false, ["encrypt", "decrypt"]);
    }

    /**
     * Calculates signature
     * 
     * @static
     * @param {CryptoKey} key
     * @param {ArrayBuffer} data
     * @returns
     * 
     * @memberOf Secret
     */
    public static async sign(key: CryptoKey, data: ArrayBuffer) {
        return await crypto.subtle.sign({ name: HMAC_NAME, hash: HASH_NAME }, key, data);
    }

    /**
     * HKDF rfc5869
     * 
     * @static
     * @param {ArrayBuffer} IKM input keying material
     * @param {number} [keysCount] amount of calculated keys
     * @param {CryptoKey} [salt] salt value (a non-secret random value)
     * - if not provided, it is set to a string of HashLen zeros.
     * @param {any} [info=new ArrayBuffer(0)]
     * @returns
     * 
     * @memberOf AsymmetricRatchet
     */
    public static async HKDF(IKM: ArrayBuffer, keysCount = 1, salt?: HMACCryptoKey, info = new ArrayBuffer(0)) {
        // https://www.ietf.org/rfc/rfc5869.txt
        // PRK = HMAC-Hash(salt, IKM)
        if (!salt) {
            salt = await this.importHMAC(new Uint8Array(32).buffer);
        }
        const PRKBytes = await this.sign(salt, IKM);
        const infoBuffer = new ArrayBuffer(32 + info.byteLength + 1);
        const infoArray = new Uint8Array(infoBuffer);

        /**
         * N = ceil(L/HashLen)
         * T = T(1) | T(2) | T(3) | ... | T(N)
         * OKM = first L octets of T
         * 
         * where:
         * T(0) = empty string (zero length)
         * T(1) = HMAC-Hash(PRK, T(0) | info | 0x01)
         * T(2) = HMAC-Hash(PRK, T(1) | info | 0x02)
         * T(3) = HMAC-Hash(PRK, T(2) | info | 0x03)
         */
        const PRK = await this.importHMAC(PRKBytes);
        const T: ArrayBuffer[] = [new ArrayBuffer(0)];
        for (let i = 0; i < keysCount; i++) {
            T[i + 1] = await this.sign(PRK, combine(T[i], info, new Uint8Array([i + 1]).buffer));
        }
        return T.slice(1);
    }

}
