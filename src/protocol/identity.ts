/**
 *
 * 2key-ratchet
 * Copyright (c) 2016 Peculiar Ventures, Inc
 * Based on https://whispersystems.org/docs/specifications/doubleratchet/ and
 * https://whispersystems.org/docs/specifications/x3dh/ by Open Whisper Systems
 *
 */

import { ProtobufElement, ProtobufProperty } from "tsprotobuf";
import { Curve, ECPublicKey } from "../crypto";
import { Identity } from "../data";
import { BaseProtocol } from "./base";
import { DateConverter, ECDHPublicKeyConverter, ECDSAPublicKeyConverter } from "./converter";

@ProtobufElement({ name: "Identity" })
export class IdentityProtocol extends BaseProtocol {

    public static async fill(identity: Identity) {
        const res = new IdentityProtocol();
        await res.fill(identity);
        return res;
    }

    @ProtobufProperty({ id: 1, converter: ECDSAPublicKeyConverter })
    public signingKey: ECPublicKey;

    @ProtobufProperty({ id: 2, converter: ECDHPublicKeyConverter })
    public exchangeKey: ECPublicKey;

    @ProtobufProperty({ id: 3 })
    public signature: ArrayBuffer;

    @ProtobufProperty({ id: 4, converter: DateConverter })
    public createdAt: Date;

    public async sign(key: CryptoKey) {
        this.signature = await Curve.sign(key, this.exchangeKey.serialize());
    }

    public async verify() {
        return await Curve.verify(this.signingKey, this.exchangeKey.serialize(), this.signature);
    }

    public async fill(identity: Identity) {
        this.signingKey = identity.signingKey.publicKey;
        this.exchangeKey = identity.exchangeKey.publicKey;
        this.createdAt = identity.createdAt;
        await this.sign(identity.signingKey.privateKey);
    }

}
