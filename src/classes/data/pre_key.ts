/**
 * 
 * 2key-ratchet
 * Copyright (c) 2016 Peculiar Ventures, Inc
 * Based on https://whispersystems.org/docs/specifications/doubleratchet/ and 
 * https://whispersystems.org/docs/specifications/x3dh/ by Open Whisper Systems
 * 
 */

import { DH_ALGORITHM_NAME } from "../const";
import { Curve, ECKeyPair } from "../crypto";
import { AssocStorage } from "../storage";

export class PreKey {

    public static async create(id: number) {
        const key = await Curve.generateKeyPair(DH_ALGORITHM_NAME);
        return new PreKey(id, key);
    }

    public id: number;
    public key: ECKeyPair;

    private constructor(id: number, key: ECKeyPair) {
        this.id = id;
        this.key = key;
    }

}

export class PreKeyStorage extends AssocStorage<PreKey> { }
