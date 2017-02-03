/**
 * 
 * 2key-ratchet
 * Copyright (c) 2016 Peculiar Ventures, Inc
 * Based on https://whispersystems.org/docs/specifications/doubleratchet/ and 
 * https://whispersystems.org/docs/specifications/x3dh/ by Open Whisper Systems
 * 
 */

import { DH_ALGORITHM_NAME, SIGN_ALGORITHM_NAME } from "../const";
import { Curve, ECKeyPair, ECPublicKey } from "../crypto";
import { AssocStorage } from "../storage";
import { PreKey, PreKeyStorage } from "./pre_key";

export class Identity {

    public static async create(id: number) {
        const signingKey = await Curve.generateKeyPair(SIGN_ALGORITHM_NAME);
        const exchangeKey = await Curve.generateKeyPair(DH_ALGORITHM_NAME);
        return new Identity(id, signingKey, exchangeKey);
    }

    public id: number;
    public signingKey: ECKeyPair;
    public exchangeKey: ECKeyPair;

    public preKeys: PreKeyStorage;
    public signedPreKeys: PreKeyStorage;

    public constructor(id: number, signingKey: ECKeyPair, exchangeKey: ECKeyPair) {
        this.id = id;
        this.signingKey = signingKey;
        this.exchangeKey = exchangeKey;
        this.preKeys = new PreKeyStorage();
        this.signedPreKeys = new PreKeyStorage();
    }

}

export class IdentityStorage extends AssocStorage<Identity> { }
