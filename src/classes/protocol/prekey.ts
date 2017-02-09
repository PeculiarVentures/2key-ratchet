/**
 * 
 * 2key-ratchet
 * Copyright (c) 2016 Peculiar Ventures, Inc
 * Based on https://whispersystems.org/docs/specifications/doubleratchet/ and 
 * https://whispersystems.org/docs/specifications/x3dh/ by Open Whisper Systems
 * 
 */

import { ProtobufElement, ProtobufProperty } from "tsprotobuf";
import { ECPublicKey} from "../crypto";
import { BaseProtocol } from "./base";
import {ECDHPublicKeyConverter} from "./converter";

@ProtobufElement({ name: "PreKey" })
export class PreKeyProtocol extends BaseProtocol {

    @ProtobufProperty({ id: 1, type: "uint32", required: true })
    public id: number;

    @ProtobufProperty({ id: 2, converter: ECDHPublicKeyConverter, required: true })
    public key: ECPublicKey;

}
