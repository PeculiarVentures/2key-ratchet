/**
 * 
 * 2key-ratchet
 * Copyright (c) 2016 Peculiar Ventures, Inc
 * Based on https://whispersystems.org/docs/specifications/doubleratchet/ and 
 * https://whispersystems.org/docs/specifications/x3dh/ by Open Whisper Systems
 * 
 */

import { ArrayBufferConverter, ProtobufElement, ProtobufProperty } from "tsprotobuf";
import { Curve, ECPublicKey } from "../crypto";
import { PreKeyProtocol } from "./prekey";

@ProtobufElement({ name: "PreKeySigned" })
export class PreKeySignedProtocol extends PreKeyProtocol {

    @ProtobufProperty({ id: 3, converter: ArrayBufferConverter, required: true })
    public signature: ArrayBuffer;

    public async sign(key: CryptoKey) {
        this.signature = await Curve.sign(key, this.key.serialize());
    }

    public verify(key: ECPublicKey) {
        return Curve.verify(key, this.key.serialize(), this.signature);
    }

}
