/**
 * 
 * 2key-ratchet
 * Copyright (c) 2016 Peculiar Ventures, Inc
 * Based on https://whispersystems.org/docs/specifications/doubleratchet/ and 
 * https://whispersystems.org/docs/specifications/x3dh/ by Open Whisper Systems
 * 
 */

import { Curve, ECPublicKey } from "../crypto";
import { IdentityProtocol } from "../protocol";
import { AssocStorage } from "../storage";
import { IJsonSerializable } from "../type";

export interface IJsonRemoteIdentity {
    id: number;
    /**
     * Thumbprint of signing key
     * 
     * @type {string}
     * @memberOf IJsonRemoteIdentity
     */
    thumbprint: string;
    signingKey: CryptoKey;
    exchangeKey: CryptoKey;
    signature: ArrayBuffer;
}

export class RemoteIdentity implements IJsonSerializable {

    public static fill(protocol: IdentityProtocol) {
        const res = new RemoteIdentity();
        res.fill(protocol);
        return res;
    }

    public static async fromJSON(obj: IJsonRemoteIdentity) {
        const res = new this();
        await res.fromJSON(obj);
        return res;
    }

    public id: number;
    public signingKey: ECPublicKey;
    public exchangeKey: ECPublicKey;
    public signature: ArrayBuffer;

    public fill(protocol: IdentityProtocol) {
        this.signingKey = protocol.signingKey;
        this.exchangeKey = protocol.exchangeKey;
        this.signature = protocol.signature;
    }

    public verify() {
        return Curve.verify(this.signingKey, this.exchangeKey.serialize(), this.signature);
    }

    public async toJSON() {
        return {
            id: this.id,
            thumbprint: await this.signingKey.thumbprint(),
            signingKey: await this.signingKey.key,
            exchangeKey: await this.exchangeKey.key,
            signature: this.signature,
        } as IJsonRemoteIdentity;
    }

    public async fromJSON(obj: IJsonRemoteIdentity) {
        this.id = obj.id;
        this.signature = obj.signature;
        this.signingKey = await ECPublicKey.create(obj.signingKey);
        this.exchangeKey = await ECPublicKey.create(obj.exchangeKey);

        // verify signature
        const ok = await this.verify();
        if (!ok) {
            throw new Error("Error: Wrong signature for RemoteIdentity");
        }
    }
}
