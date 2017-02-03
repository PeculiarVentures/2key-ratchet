import { ECPublicKey } from "./public_key";

export interface ECKeyPair {
    privateKey: CryptoKey;
    publicKey: ECPublicKey;
}
