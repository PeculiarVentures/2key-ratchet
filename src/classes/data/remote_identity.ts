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

export class RemoteIdentity {

    public static fill(protocol: IdentityProtocol) {
        const res = new RemoteIdentity();
        res.fill(protocol);
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
}

export class RemoteIdentityStorage extends AssocStorage<RemoteIdentity> { }
