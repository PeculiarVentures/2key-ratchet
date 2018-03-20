/**
 *
 * 2key-ratchet
 * Copyright (c) 2016 Peculiar Ventures, Inc
 * Based on https://whispersystems.org/docs/specifications/doubleratchet/ and
 * https://whispersystems.org/docs/specifications/x3dh/ by Open Whisper Systems
 *
 */

import { DH_ALGORITHM_NAME, SIGN_ALGORITHM_NAME } from "../const";
import { Curve, ECPublicKey, IECKeyPair } from "../crypto";
import { AssocStorage } from "../storage";
import { IJsonSerializable } from "../type";

export interface IJsonIdentity {
    id: number;
    signingKey: CryptoKeyPair;
    exchangeKey: CryptoKeyPair;
    preKeys: CryptoKeyPair[];
    signedPreKeys: CryptoKeyPair[];
    createdAt: string;
}

export class Identity implements IJsonSerializable {

    public static async fromJSON(obj: IJsonIdentity) {
        const signingKey = await Curve.ecKeyPairFromJson(obj.signingKey);
        const exchangeKey = await Curve.ecKeyPairFromJson(obj.exchangeKey);
        const res = new this(obj.id, signingKey, exchangeKey);
        res.createdAt = new Date(obj.createdAt);
        await res.fromJSON(obj);
        return res;
    }

    public static async create(id: number, signedPreKeyAmount = 0, preKeyAmount = 0) {
        const signingKey = await Curve.generateKeyPair(SIGN_ALGORITHM_NAME);
        const exchangeKey = await Curve.generateKeyPair(DH_ALGORITHM_NAME);
        const res = new Identity(id, signingKey, exchangeKey);
        res.createdAt = new Date();
        // generate preKey
        for (let i = 0; i < preKeyAmount; i++) {
            res.preKeys.push(await Curve.generateKeyPair("ECDH"));
        }
        // generate signedPreKey
        for (let i = 0; i < signedPreKeyAmount; i++) {
            res.signedPreKeys.push(await Curve.generateKeyPair("ECDH"));
        }
        return res;
    }

    public id: number;
    public signingKey: IECKeyPair;
    public exchangeKey: IECKeyPair;
    public createdAt: Date;

    public preKeys: IECKeyPair[];
    public signedPreKeys: IECKeyPair[];

    protected constructor(id: number, signingKey: IECKeyPair, exchangeKey: IECKeyPair) {
        this.id = id;
        this.signingKey = signingKey;
        this.exchangeKey = exchangeKey;
        this.preKeys = [];
        this.signedPreKeys = [];
    }

    public async toJSON() {
        const preKeys: CryptoKeyPair[] = [];
        const signedPreKeys: CryptoKeyPair[] = [];
        for (const key of this.preKeys) {
            preKeys.push(await Curve.ecKeyPairToJson(key));
        }
        for (const key of this.signedPreKeys) {
            signedPreKeys.push(await Curve.ecKeyPairToJson(key));
        }
        return {
            createdAt: this.createdAt.toISOString(),
            exchangeKey: await Curve.ecKeyPairToJson(this.exchangeKey),
            id: this.id,
            preKeys,
            signedPreKeys,
            signingKey: await Curve.ecKeyPairToJson(this.signingKey),
        } as IJsonIdentity;
    }

    public async fromJSON(obj: IJsonIdentity) {
        this.id = obj.id;
        this.signingKey = await Curve.ecKeyPairFromJson(obj.signingKey);
        this.exchangeKey = await Curve.ecKeyPairFromJson(obj.exchangeKey);
        this.preKeys = [];
        for (const key of obj.preKeys) {
            this.preKeys.push(await Curve.ecKeyPairFromJson(key));
        }
        this.signedPreKeys = [];
        for (const key of obj.signedPreKeys) {
            this.signedPreKeys.push(await Curve.ecKeyPairFromJson(key));
        }
    }

}
