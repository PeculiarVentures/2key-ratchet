/**
 *
 * 2key-ratchet
 * Copyright (c) 2016 Peculiar Ventures, Inc
 * Based on https://whispersystems.org/docs/specifications/doubleratchet/ and
 * https://whispersystems.org/docs/specifications/x3dh/ by Open Whisper Systems
 *
 */

import { ProtobufElement, ProtobufProperty } from "tsprotobuf";
import { BaseProtocol } from "./base";
import { IdentityProtocol } from "./identity";
import { PreKeyProtocol } from "./prekey";
import { PreKeySignedProtocol } from "./prekey_signed";

@ProtobufElement({ name: "PreKeyBundle" })
export class PreKeyBundleProtocol extends BaseProtocol {

    @ProtobufProperty({ id: 1, type: "uint32", required: true })
    public registrationId: number;

    @ProtobufProperty({ id: 2, parser: IdentityProtocol, required: true })
    public identity: IdentityProtocol;

    @ProtobufProperty({ id: 3, parser: PreKeyProtocol })
    public preKey: PreKeyProtocol;

    @ProtobufProperty({ id: 4, parser: PreKeySignedProtocol, required: true })
    public preKeySigned: PreKeySignedProtocol;

}
