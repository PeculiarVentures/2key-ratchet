/**
 *
 * 2key-ratchet
 * Copyright (c) 2016 Peculiar Ventures, Inc
 * Based on https://whispersystems.org/docs/specifications/doubleratchet/ and
 * https://whispersystems.org/docs/specifications/x3dh/ by Open Whisper Systems
 *
 */

import { Convert } from "pvtsutils";
import { INFO_MESSAGE_KEYS } from "./const";
import { IECKeyPair, ECPublicKey, Secret } from "./crypto";
import { HMACCryptoKey, ISymmetricKDFResult, RatchetKey } from "./type";
import { IJsonSerializable } from "./type";

// Constants for KDF_CK function
const CIPHER_KEY_KDF_INPUT = new Uint8Array([1]).buffer;
const ROOT_KEY_KDF_INPUT = new Uint8Array([2]).buffer;

/**
 * Encrypt/Decrypt result for Symmetric ratchets
 *
 * @export
 * @interface CipherMessage
 */
export interface ICipherMessage {
    /**
     * Encrypted or decrypted message
     */
    cipherText: ArrayBuffer;
    /**
     * HMAC key for SignedMessage calculations
     */
    hmacKey: CryptoKey;
}

export interface IJsonSymmetricRatchet {
    counter: number;
    rootKey: CryptoKey;
}

export abstract class SymmetricRatchet implements IJsonSerializable {

    public static async fromJSON<T extends SymmetricRatchet>(
        this: { new (rootKey: CryptoKey): T },
        obj: IJsonSymmetricRatchet,
    ) {
        const res = new this(obj.rootKey);
        res.fromJSON(obj);
        return res;
    }

    public counter = 0;

    /**
     * Current symmetric ratchet key
     */
    public rootKey: HMACCryptoKey;

    constructor(rootKey: CryptoKey) {
        this.rootKey = rootKey;
    }

    public async toJSON() {
        return {
            counter: this.counter,
            rootKey: this.rootKey,
        } as IJsonSymmetricRatchet;
    }

    public async fromJSON(obj: IJsonSymmetricRatchet) {
        this.counter = obj.counter;
        this.rootKey = obj.rootKey;
    }

    /**
     * calculates new keys by rootKey KDF_CK(ck)
     * https://whispersystems.org/docs/specifications/doubleratchet/#external-functions
     *
     * @protected
     * @param {CryptoKey} rootKey
     * @returns
     *
     * @memberOf SymmetricRatchet
     */
    protected async calculateKey(rootKey: CryptoKey) {
        const cipherKeyBytes = await Secret.sign(rootKey, CIPHER_KEY_KDF_INPUT);
        const nextRootKeyBytes = await Secret.sign(rootKey, ROOT_KEY_KDF_INPUT);

        const res: ISymmetricKDFResult = {
            cipher: cipherKeyBytes,
            rootKey: await Secret.importHMAC(nextRootKeyBytes),
        };
        return res;
    }

    /**
     * Move to next step of ratchet
     *
     * @protected
     * @returns
     *
     * @memberOf SymmetricRatchet
     */
    protected async click() {
        const rootKey = this.rootKey;
        const res = await this.calculateKey(rootKey);
        this.rootKey = res.rootKey;
        this.counter++;
        return res.cipher;
    }

}

/**
 * Implementation of Sending chain
 *
 * @export
 * @class SendingRatchet
 * @extends {SymmetricRatchet}
 */
export class SendingRatchet extends SymmetricRatchet {

    /**
     * Encrypts message
     *
     * @param {ArrayBuffer} message
     * @returns CipherMessage type
     *
     * @memberOf SendingRatchet
     */
    public async encrypt(message: ArrayBuffer) {
        const cipherKey = await this.click();
        // calculate keys
        const keys = await Secret.HKDF(cipherKey, 3, void 0, INFO_MESSAGE_KEYS);
        const aesKey = await Secret.importAES(keys[0]);
        const hmacKey = await Secret.importHMAC(keys[1]);
        const iv = keys[2].slice(0, 16);

        const cipherText = await Secret.encrypt(aesKey, message, iv);

        return {
            cipherText,
            hmacKey,
        } as ICipherMessage;
    }

}

export interface IJsonReceivingRatchet extends IJsonSymmetricRatchet {
    keys: ArrayBuffer[];
}

export class ReceivingRatchet extends SymmetricRatchet {

    protected keys: ArrayBuffer[] = [];

    public async toJSON() {
        const res: IJsonReceivingRatchet = (await super.toJSON()) as any;
        res.keys = this.keys;
        return res;
    }

    public async fromJSON(obj: IJsonReceivingRatchet) {
        await super.fromJSON(obj);
        this.keys = obj.keys;
    }

    public async decrypt(message: ArrayBuffer, counter: number) {
        const cipherKey = await this.getKey(counter);
        // calculate keys
        const keys = await Secret.HKDF(cipherKey, 3, void 0, INFO_MESSAGE_KEYS);
        const aesKey = await Secret.importAES(keys[0]);
        const hmacKey = await Secret.importHMAC(keys[1]);
        const iv = keys[2].slice(0, 16);

        const cipherText = await Secret.decrypt(aesKey, message, iv);

        return {
            cipherText,
            hmacKey,
        } as ICipherMessage;
    }

    protected async getKey(counter: number) {
        while (this.counter <= counter) {
            const cipherKey = await this.click();
            this.keys.push(cipherKey);
        }
        const key = this.keys[counter];
        return key;
    }
}
