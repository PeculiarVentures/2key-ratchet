/**
 * 
 * 2key-ratchet
 * Copyright (c) 2016 Peculiar Ventures, Inc
 * Based on https://whispersystems.org/docs/specifications/doubleratchet/ and 
 * https://whispersystems.org/docs/specifications/x3dh/ by Open Whisper Systems
 * 
 */

import * as utils from "pvtsutils";
import { ProtobufElement, ProtobufProperty } from "tsprotobuf";
import { Curve, ECPublicKey, Secret } from "../crypto";
import { BaseProtocol } from "./base";
import { ECDSAPublicKeyConverter } from "./converter";
import { MessageProtocol } from "./message";

@ProtobufElement({ name: "MessageSigned" })
export class MessageSignedProtocol extends BaseProtocol {

    public receiverKey: ECPublicKey;

    @ProtobufProperty({ id: 1, converter: ECDSAPublicKeyConverter, required: true })
    public senderKey: ECPublicKey;

    @ProtobufProperty({ id: 2, parser: MessageProtocol, required: true })
    public message: MessageProtocol;

    @ProtobufProperty({ id: 3, required: true })
    protected signature: ArrayBuffer;

    public async sign(hmacKey: CryptoKey) {
        this.signature = await this.signHMAC(hmacKey);
    }

    public async verify(hmacKey: CryptoKey) {
        const signature = await this.signHMAC(hmacKey);
        return utils.isEqual(signature, this.signature);
    }

    protected async getSignedRaw() {
        const receiverKey = this.receiverKey.serialize();
        const senderKey = this.senderKey.serialize();
        const message = await this.message.exportProto();

        const data = utils.combine(receiverKey, senderKey, message);
        return data;
    }

    protected async signHMAC(macKey: CryptoKey) {
        const data = await this.getSignedRaw();

        const signature = await Secret.sign(macKey, data);
        return signature;
    }

}
