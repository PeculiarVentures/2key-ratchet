import { IECKeyPair } from "./crypto/key_pair";

export type ECDHPublicKey = CryptoKey;
export type ECDSAPublicKey = CryptoKey;
export type ECDHPrivateKey = CryptoKey;
export type RatchetKey = ECDHPublicKey;
export type RatchetKeyPair = CryptoKeyPair;
export type HMACCryptoKey = CryptoKey;

export type ECKeyType = "ECDH" | "ECDSA";

export interface IDHRatchetItem {
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

export interface ISymmetricKDFResult2 {
    rootKey: CryptoKey;
    bytes: Uint8Array;
}

export interface ISymmetricKDFResult {
    cipher: ArrayBuffer;
    rootKey: CryptoKey;
}

export interface IMessageProtocol {
    ratchetKey: ECDHPublicKey;
    message: ArrayBuffer;
    counter: number;
}

export interface IIdentityKeyPair {
    signingKey: IECKeyPair;
    exchangeKey: IECKeyPair;
    signature: ArrayBuffer;
}

export interface IPreKeyPair {
    id: number;
    key: IECKeyPair;
}

export interface IPreKeySignedPair extends IPreKeyPair {
    signature: ArrayBuffer;
}

export interface IJsonSerializable {
    toJSON(): Promise<any>;
    fromJSON(obj: any): Promise<void>;
}
