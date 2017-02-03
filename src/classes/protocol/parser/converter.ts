/**
 * 
 * 2key-ratchet
 * Copyright (c) 2016 Peculiar Ventures, Inc
 * Based on https://whispersystems.org/docs/specifications/doubleratchet/ and 
 * https://whispersystems.org/docs/specifications/x3dh/ by Open Whisper Systems
 * 
 */

import { ECPublicKey } from "../../crypto";
export interface IConverter<In> {
    set: (value: In) => PromiseLike<Uint8Array>;
    get: (value: Uint8Array) => PromiseLike<In>;
}

export class ArrayBufferConverter {
    public static async set(value: ArrayBuffer) {
        return new Uint8Array(value);
    }
    public static async get(value: Uint8Array) {
        return value.buffer;
    };
}

export class ECDSAPublicKeyConverter {
    public static async set(value: ECPublicKey) {
        return new Uint8Array(value.serialize());
    }
    public static async get(value: Uint8Array) {
        return ECPublicKey.importKey(value.buffer, "ECDSA");
    };
}

export class ECDHPublicKeyConverter {
    public static async set(value: ECPublicKey) {
        return new Uint8Array(value.serialize());
    }
    public static async get(value: Uint8Array) {
        return ECPublicKey.importKey(value.buffer, "ECDH");
    };
}
