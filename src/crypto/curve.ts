/**
 *
 * 2key-ratchet
 * Copyright (c) 2016 Peculiar Ventures, Inc
 * Based on https://whispersystems.org/docs/specifications/doubleratchet/ and
 * https://whispersystems.org/docs/specifications/x3dh/ by Open Whisper Systems
 *
 */

import { ECDHPrivateKey, ECKeyType } from "../type";
import { getEngine } from "./crypto";
import { IECKeyPair } from "./key_pair";
import { ECPublicKey } from "./public_key";

export class Curve {

    public static NAMED_CURVE = "P-256";
    public static DIGEST_ALGORITHM = "SHA-512";

    /**
     * Generates new EC key pair
     *
     * @static
     * @param {ECKeyType} type type of EC key. ECDSA | ECDH
     * @returns
     *
     * @memberOf Curve
     */
    public static async generateKeyPair(type: ECKeyType) {
        const name = type;
        const usage = type === "ECDSA" ? ["sign", "verify"] : ["deriveKey", "deriveBits"];
        const keys = await getEngine().crypto.subtle.generateKey({ name, namedCurve: this.NAMED_CURVE }, false, usage);
        const publicKey = await ECPublicKey.create(keys.publicKey);
        const res: IECKeyPair = {
            privateKey: keys.privateKey,
            publicKey,
        };
        return res;
    }

    /**
     * Derives 32 bytes from EC keys
     *
     * @static
     * @param {ECDHPrivateKey} privateKey EC private key
     * @param {ECPublicKey} publicKey EC public key
     * @returns
     *
     * @memberOf Curve
     */
    public static deriveBytes(privateKey: ECDHPrivateKey, publicKey: ECPublicKey) {
        return getEngine().crypto.subtle.deriveBits({ name: "ECDH", public: publicKey.key }, privateKey, 256);
    }

    /**
     * Verifies signature
     *
     * @static
     * @param {ECPublicKey} signingKey
     * @param {ArrayBuffer} message
     * @param {ArrayBuffer} signature
     * @returns
     *
     * @memberOf Curve
     */
    public static verify(signingKey: ECPublicKey, message: ArrayBuffer, signature: ArrayBuffer) {
        return getEngine().crypto.subtle
            .verify({ name: "ECDSA", hash: this.DIGEST_ALGORITHM }, signingKey.key, signature, message);
    }

    /**
     * Calculates signature
     *
     * @static
     * @param {ECDHPrivateKey} signingKey
     * @param {ArrayBuffer} message
     * @returns
     *
     * @memberOf Curve
     */
    public static async sign(signingKey: ECDHPrivateKey, message: ArrayBuffer) {
        return getEngine().crypto.subtle.sign({ name: "ECDSA", hash: this.DIGEST_ALGORITHM }, signingKey, message);
    }

    public static async ecKeyPairToJson(key: IECKeyPair) {
        return {
            privateKey: key.privateKey,
            publicKey: key.publicKey.key,
            thumbprint: await key.publicKey.thumbprint(),
        } as CryptoKeyPair;
    }

    public static async ecKeyPairFromJson(keys: CryptoKeyPair) {
        return {
            privateKey: keys.privateKey,
            publicKey: await ECPublicKey.create(keys.publicKey),
        } as IECKeyPair;
    }

}
