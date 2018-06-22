/**
 *
 * 2key-ratchet
 * Copyright (c) 2016 Peculiar Ventures, Inc
 * Based on https://whispersystems.org/docs/specifications/doubleratchet/ and
 * https://whispersystems.org/docs/specifications/x3dh/ by Open Whisper Systems
 *
 */

import { Convert, isEqual } from "pvtsutils";
import { ECKeyType } from "../type";
import { getEngine } from "./crypto";
import { Curve } from "./curve";
import { Secret } from "./secret";

/**
 * Implementation of EC public key
 *
 * @export
 * @class ECPublicKey
 */
export class ECPublicKey {

    /**
     * Creates new instance of ECPublicKey from CryptoKey
     *
     * @static
     * @param {CryptoKey} publicKey
     * @returns
     *
     * @memberOf ECPublicKey
     */
    public static async create(publicKey: CryptoKey) {
        const res = new this();
        const algName = publicKey.algorithm.name!.toUpperCase();
        if (!(algName === "ECDH" || algName === "ECDSA")) {
            throw new Error("Error: Unsupported asymmetric key algorithm.");
        }
        if (publicKey.type !== "public") {
            throw new Error("Error: Expected key type to be public but it was not.");
        }
        res.key = publicKey;

        // Serialize public key to JWK
        const jwk = await getEngine().crypto.subtle.exportKey("jwk", publicKey);
        if (!(jwk.x && jwk.y)) {
            throw new Error("Wrong JWK data for EC public key. Parameters x and y are required.");
        }
        const x = Convert.FromBase64Url(jwk.x);
        const y = Convert.FromBase64Url(jwk.y);
        const xy = Convert.ToBinary(x) + Convert.ToBinary(y);
        res.serialized = Convert.FromBinary(xy);
        res.id = await res.thumbprint();

        return res;
    }

    /**
     * Creates ECPublicKey from raw data
     *
     * @static
     * @param {ArrayBuffer} bytes
     * @param {ECKeyType} type type of EC key. ECDSA | ECDH
     * @returns
     *
     * @memberOf ECPublicKey
     */
    public static async importKey(bytes: ArrayBuffer, type: ECKeyType) {
        const x = Convert.ToBase64Url(bytes.slice(0, 32));
        const y = Convert.ToBase64Url(bytes.slice(32));
        const jwk = {
            crv: Curve.NAMED_CURVE,
            kty: "EC",
            x,
            y,
        };
        const usage = (type === "ECDSA" ? ["verify"] : []);
        const key = await getEngine().crypto.subtle
            .importKey("jwk", jwk, { name: type, namedCurve: Curve.NAMED_CURVE }, true, usage);
        const res = await ECPublicKey.create(key);
        return res;
    }

    /**
     * Identity of ECPublicKey
     * HEX string of thumbprint of EC key
     *
     * @type {string}
     * @memberOf ECPublicKey
     */
    public id: string;

    /**
     * Crypto key
     *
     * @type {CryptoKey}
     * @memberOf ECPublicKey
     */
    public key: CryptoKey;

    /**
     * raw data of key
     *
     * @protected
     * @type {ArrayBuffer}
     * @memberOf ECPublicKey
     */
    protected serialized: ArrayBuffer;

    /**
     * Returns key in raw format
     *
     * @returns
     *
     * @memberOf ECPublicKey
     */
    public serialize() {
        return this.serialized;
    }

    /**
     * Returns SHA-256 digest of key
     *
     * @returns
     *
     * @memberOf ECPublicKey
     */
    public async thumbprint() {
        const bytes = await this.serialize();
        const thumbprint = await Secret.digest("SHA-256", bytes);
        return Convert.ToHex(thumbprint);
    }

    /**
     * Returns `true` if current is equal to given parameter
     *
     * @param {*} other
     * @returns
     *
     * @memberOf ECPublicKey
     */
    public async isEqual(other: any) {
        if (!(other && other instanceof ECPublicKey)) { return false; }

        return isEqual(this.serialized, other.serialized);
    }

}
