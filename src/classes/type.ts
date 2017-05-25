import { ECKeyPair } from "./crypto/key_pair";

export type ECDHPublicKey = CryptoKey;
export type ECDSAPublicKey = CryptoKey;
export type ECDHPrivateKey = CryptoKey;
export type RatchetKey = ECDHPublicKey;
export type RatchetKeyPair = CryptoKeyPair;
export type HMACCryptoKey = CryptoKey;

export type ECKeyType = "ECDH" | "ECDSA";

export interface DHRatchetItem {
    key: RatchetKeyPair;
}

export interface Identity {
    /**
     * remote client's string identity
     */
    id: string;
    /**
     * Remote client's
     */
    key: ECDSAPublicKey;
}

export interface ISession {
    identityId: string;
}

export interface SymmetricKDFResult2 {
    rootKey: CryptoKey;
    bytes: Uint8Array;
}

export interface SymmetricKDFResult {
    cipher: ArrayBuffer;
    rootKey: CryptoKey;
}

export interface MessageProtocol {
    ratchetKey: ECDHPublicKey;
    message: ArrayBuffer;
    counter: number;
}

export interface IIdentityKeyPair {
    signingKey: ECKeyPair;
    exchangeKey: ECKeyPair;
    signature: ArrayBuffer;
}

export interface IPreKeyPair {
    id: number;
    key: ECKeyPair;
}

export interface IPreKeySignedPair extends IPreKeyPair {
    signature: ArrayBuffer;
}

export interface IJsonSerializable {
    toJSON(): Promise<any>;
    fromJSON(obj: any): Promise<void>;
}
