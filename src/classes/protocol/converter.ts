/**
 *
 * 2key-ratchet
 * Copyright (c) 2016 Peculiar Ventures, Inc
 * Based on https://whispersystems.org/docs/specifications/doubleratchet/ and
 * https://whispersystems.org/docs/specifications/x3dh/ by Open Whisper Systems
 *
 */

import { Convert } from "pvtsutils";
import { ECPublicKey } from "../crypto";

export class ECDSAPublicKeyConverter {
    public static async set(value: ECPublicKey) {
        return new Uint8Array(value.serialize());
    }
    public static async get(value: Uint8Array) {
        return ECPublicKey.importKey(value.buffer, "ECDSA");
    }
}

export class ECDHPublicKeyConverter {
    public static async set(value: ECPublicKey) {
        return new Uint8Array(value.serialize());
    }
    public static async get(value: Uint8Array) {
        return ECPublicKey.importKey(value.buffer, "ECDH");
    }
}

export class DateConverter {
    public static async set(value: Date) {
        return new Uint8Array(Convert.FromString(value.toISOString()));
    }
    public static async get(value: Uint8Array) {
        return new Date(Convert.ToString(value));
    }
}
