/**
 *
 * 2key-ratchet
 * Copyright (c) 2016 Peculiar Ventures, Inc
 * Based on https://whispersystems.org/docs/specifications/doubleratchet/ and
 * https://whispersystems.org/docs/specifications/x3dh/ by Open Whisper Systems
 *
 */

import { ArrayBufferConverter, ProtobufElement, ProtobufProperty } from "tsprotobuf";
import { ECPublicKey } from "../crypto";
import { BaseProtocol } from "./base";
import { ECDHPublicKeyConverter } from "./converter";

@ProtobufElement({ name: "Message" })
export class MessageProtocol extends BaseProtocol {

    @ProtobufProperty({ id: 1, converter: ECDHPublicKeyConverter, required: true })
    public senderRatchetKey: ECPublicKey;

    @ProtobufProperty({ id: 2, type: "uint32", required: true })
    public counter: number;

    @ProtobufProperty({ id: 3, type: "uint32", required: true })
    public previousCounter: number;

    @ProtobufProperty({ id: 4, converter: ArrayBufferConverter, required: true })
    public cipherText: ArrayBuffer;

}
