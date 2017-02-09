/**
 * 
 * 2key-ratchet
 * Copyright (c) 2016 Peculiar Ventures, Inc
 * Based on https://whispersystems.org/docs/specifications/doubleratchet/ and 
 * https://whispersystems.org/docs/specifications/x3dh/ by Open Whisper Systems
 * 
 */

import { ProtobufElement, ProtobufProperty } from "tsprotobuf";
import { ECPublicKey } from "../crypto/public_key";
import { BaseProtocol } from "./base";
import {ECDHPublicKeyConverter} from "./converter";
import { IdentityProtocol } from "./identity";
import { MessageSignedProtocol } from "./message_signed";

@ProtobufElement({ name: "PreKeyMessage" })
export class PreKeyMessageProtocol extends BaseProtocol {

    @ProtobufProperty({ id: 1, type: "uint32", required: true })
    public registrationId: number;

    @ProtobufProperty({ id: 2, type: "uint32" })
    public preKeyId: number;

    @ProtobufProperty({ id: 3, type: "uint32", required: true })
    public preKeySignedId: number;

    @ProtobufProperty({ id: 4, converter: ECDHPublicKeyConverter, required: true })
    public baseKey: ECPublicKey;

    @ProtobufProperty({ id: 5, parser: IdentityProtocol, required: true })
    public identity: IdentityProtocol;

    @ProtobufProperty({ id: 6, parser: MessageSignedProtocol, required: true })
    public signedMessage: MessageSignedProtocol;

}
