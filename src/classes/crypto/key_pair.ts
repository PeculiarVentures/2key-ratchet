/**
 *
 * 2key-ratchet
 * Copyright (c) 2016 Peculiar Ventures, Inc
 * Based on https://whispersystems.org/docs/specifications/doubleratchet/ and
 * https://whispersystems.org/docs/specifications/x3dh/ by Open Whisper Systems
 *
 */

import { ECPublicKey } from "./public_key";

export interface IECKeyPair {
    privateKey: CryptoKey;
    publicKey: ECPublicKey;
}
