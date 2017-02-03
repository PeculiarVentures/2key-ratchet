/**
 * 
 * 2key-ratchet
 * Copyright (c) 2016 Peculiar Ventures, Inc
 * Based on https://whispersystems.org/docs/specifications/doubleratchet/ and 
 * https://whispersystems.org/docs/specifications/x3dh/ by Open Whisper Systems
 * 
 */

import { ProtobufElement, ProtobufProperty, ProtocolObject } from "./parser";

@ProtobufElement({ localName: "Base" })
export abstract class BaseProtocol extends ProtocolObject {

    @ProtobufProperty({ id: 0, type: "uint32", defaultValue: 1 })
    public version: number;

}
