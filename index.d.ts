import {ObjectProto} from "tsprotobuf"; 

declare namespace DKeyRatchet {

    // types

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

    export interface SymmetricKDFResult {
        cipher: ArrayBuffer;
        rootKey: CryptoKey;
    }

    // crypto

    /**
     * Implementation of EC public key
     *
     * @export
     * @class ECPublicKey
     */
    export class ECPublicKey {
        /**
         * Creates new instance of ECPublicKey from CryptoKey
         *
         * @static
         * @param {CryptoKey} publicKey
         * @returns
         *
         * @memberOf ECPublicKey
         */
        static create(publicKey: CryptoKey): Promise<ECPublicKey>;
        /**
         * Creates ECPublicKey from raw data
         *
         * @static
         * @param {ArrayBuffer} bytes
         * @param {ECKeyType} type type of EC key. ECDSA | ECDH
         * @returns
         *
         * @memberOf ECPublicKey
         */
        static importKey(bytes: ArrayBuffer, type: ECKeyType): Promise<ECPublicKey>;
        /**
         * Identity of ECPublicKey
         * HEX string of thumbprint of EC key
         *
         * @type {string}
         * @memberOf ECPublicKey
         */
        id: string;
        /**
         * Crypto key
         *
         * @type {CryptoKey}
         * @memberOf ECPublicKey
         */
        key: CryptoKey;
        /**
         * raw data of key
         *
         * @protected
         * @type {ArrayBuffer}
         * @memberOf ECPublicKey
         */
        protected serialized: ArrayBuffer;
        /**
         * Returns key in raw format
         *
         * @returns
         *
         * @memberOf ECPublicKey
         */
        serialize(): ArrayBuffer;
        /**
         * Returns SHA-1 digest of key
         *
         * @returns
         *
         * @memberOf ECPublicKey
         */
        thumbprint(): Promise<string>;
        /**
         * Returns `true` if current is equal to given parameter
         *
         * @param {*} other
         * @returns
         *
         * @memberOf ECPublicKey
         */
        isEqual(other: any): Promise<boolean>;
    }

    export interface ECKeyPair {
        privateKey: CryptoKey;
        publicKey: ECPublicKey;
    }

    export class Curve {
        static NAMED_CURVE: string;
        static DIGEST_ALGORITHM: string;
        /**
         * Generates new EC key pair
         *
         * @static
         * @param {ECKeyType} type type of EC key. ECDSA | ECDH
         * @returns
         *
         * @memberOf Curve
         */
        static generateKeyPair(type: ECKeyType): Promise<ECKeyPair>;
        /**
         * Derives 32 bytes from EC keys
         *
         * @static
         * @param {ECDHPrivateKey} privateKey EC private key
         * @param {ECPublicKey} publicKey EC public key
         * @returns
         *
         * @memberOf Curve
         */
        static deriveBytes(privateKey: ECDHPrivateKey, publicKey: ECPublicKey): PromiseLike<ArrayBuffer>;
        /**
         * Verifies signature
         *
         * @static
         * @param {ECPublicKey} signingKey
         * @param {ArrayBuffer} message
         * @param {ArrayBuffer} signature
         * @returns
         *
         * @memberOf Curve
         */
        static verify(signingKey: ECPublicKey, message: ArrayBuffer, signature: ArrayBuffer): PromiseLike<boolean>;
        /**
         * Calculates signature
         *
         * @static
         * @param {ECDHPrivateKey} signingKey
         * @param {ArrayBuffer} message
         * @returns
         *
         * @memberOf Curve
         */
        static sign(signingKey: ECDHPrivateKey, message: ArrayBuffer): Promise<ArrayBuffer>;
    }

    export class Secret {
        static subtle: SubtleCrypto;
        /**
         * Returns ArrayBuffer of random bytes
         *
         * @static
         * @param {number} size size of output buffer
         * @returns
         *
         * @memberOf Secret
         */
        static randomBytes(size: number): ArrayBuffer;
        /**
         * Calculates digest
         *
         * @static
         * @param {string} alg
         * @param {ArrayBuffer} message
         * @returns
         *
         * @memberOf Secret
         */
        static digest(alg: string, message: ArrayBuffer): PromiseLike<ArrayBuffer>;
        /**
         * Encrypts data
         *
         * @static
         * @param {CryptoKey} key
         * @param {ArrayBuffer} data
         * @param {ArrayBuffer} iv
         * @returns
         *
         * @memberOf Secret
         */
        static encrypt(key: CryptoKey, data: ArrayBuffer, iv: ArrayBuffer): PromiseLike<ArrayBuffer>;
        /**
         * Decrypts data
         *
         * @static
         * @param {CryptoKey} key
         * @param {ArrayBuffer} data
         * @param {ArrayBuffer} iv
         * @returns
         *
         * @memberOf Secret
         */
        static decrypt(key: CryptoKey, data: ArrayBuffer, iv: ArrayBuffer): PromiseLike<ArrayBuffer>;
        /**
         * Creates HMAC key from raw data
         *
         * @static
         * @param {ArrayBuffer} raw
         * @returns
         *
         * @memberOf Secret
         */
        static importHMAC(raw: ArrayBuffer): PromiseLike<CryptoKey>;
        /**
         * Creates AES key from raw data
         *
         * @static
         * @param {ArrayBuffer} raw
         * @returns
         *
         * @memberOf Secret
         */
        static importAES(raw: ArrayBuffer): PromiseLike<CryptoKey>;
        /**
         * Calculates signature
         *
         * @static
         * @param {CryptoKey} key
         * @param {ArrayBuffer} data
         * @returns
         *
         * @memberOf Secret
         */
        static sign(key: CryptoKey, data: ArrayBuffer): Promise<ArrayBuffer>;
        /**
         * HKDF rfc5869
         *
         * @static
         * @param {ArrayBuffer} IKM input keying material
         * @param {number} [keysCount] amount of calculated keys
         * @param {CryptoKey} [salt] salt value (a non-secret random value)
         * - if not provided, it is set to a string of HashLen zeros.
         * @param {any} [info=new ArrayBuffer(0)]
         * @returns
         *
         * @memberOf AsymmetricRatchet
         */
        static HKDF(IKM: ArrayBuffer, keysCount?: number, salt?: HMACCryptoKey, info?: ArrayBuffer): Promise<ArrayBuffer[]>;
    }

    // data

    export class Address {
        protected static readonly SPLITTER: string;
        name: string;
        id: number;
        constructor(name: string, id: number);
        toString(): string;
    }

    export class Identity {
        static create(id: number): Promise<Identity>;
        id: number;
        signingKey: ECKeyPair;
        exchangeKey: ECKeyPair;
        preKeys: PreKeyStorage;
        signedPreKeys: PreKeyStorage;
        constructor(id: number, signingKey: ECKeyPair, exchangeKey: ECKeyPair);
    }
    export class IdentityStorage extends AssocStorage<Identity> {
    }

    export class PreKey {
        static create(id: number): Promise<PreKey>;
        id: number;
        key: ECKeyPair;
        private constructor(id, key);
    }
    export class PreKeyStorage extends AssocStorage<PreKey> {
    }

    export class RemoteIdentity {
        static fill(protocol: IdentityProtocol): RemoteIdentity;
        id: number;
        signingKey: ECPublicKey;
        exchangeKey: ECPublicKey;
        signature: ArrayBuffer;
        fill(protocol: IdentityProtocol): void;
        verify(): PromiseLike<boolean>;
    }
    export class RemoteIdentityStorage extends AssocStorage<RemoteIdentity> {
    }

    // protocol

    export abstract class BaseProtocol extends ObjectProto {
        version: number;
    }

    export class IdentityProtocol extends BaseProtocol {
        static fill(identity: Identity): Promise<IdentityProtocol>;
        signingKey: ECPublicKey;
        exchangeKey: ECPublicKey;
        signature: ArrayBuffer;
        sign(key: CryptoKey): Promise<void>;
        verify(): Promise<boolean>;
        fill(identity: Identity): Promise<void>;
    }

    export class MessageProtocol extends BaseProtocol {
        senderRatchetKey: ECPublicKey;
        counter: number;
        previousCounter: number;
        cipherText: ArrayBuffer;
    }

    export class MessageSignedProtocol extends BaseProtocol {
        receiverKey: ECPublicKey;
        senderKey: ECPublicKey;
        message: MessageProtocol;
        protected signature: ArrayBuffer;
        sign(hmacKey: CryptoKey): Promise<void>;
        verify(hmacKey: CryptoKey): Promise<boolean>;
        protected getSignedRaw(): Promise<ArrayBuffer>;
        protected signHMAC(macKey: CryptoKey): Promise<ArrayBuffer>;
    }

    export class PreKeyMessageProtocol extends BaseProtocol {
        registrationId: number;
        preKeyId: number;
        preKeySignedId: number;
        baseKey: ECPublicKey;
        identity: IdentityProtocol;
        signedMessage: MessageSignedProtocol;
    }

    export class PreKeyProtocol extends BaseProtocol {
        id: number;
        key: ECPublicKey;
    }

    export class PreKeySignedProtocol extends PreKeyProtocol {
        signature: ArrayBuffer;
        sign(key: CryptoKey): Promise<void>;
        verify(key: ECPublicKey): PromiseLike<boolean>;
    }

    export class PreKeyBundleProtocol extends BaseProtocol {
        registrationId: number;
        identity: IdentityProtocol;
        preKey: PreKeyProtocol;
        preKeySigned: PreKeySignedProtocol;
    }

    // core

    export class Stack<T> {
        protected items: T[];
        protected maxSize: number;
        readonly length: number;
        readonly latest: T;
        constructor(maxSize?: number);
        push(item: T): void;
    }

    export class AssocStorage<T> {
        protected items: {
            [key: string]: T;
        };
        readonly length: number;
        save(key: string, value: T): void;
        load(key: string): T;
        remove(key: string): void;
        clear(): void;
    }

    /**
     * Implementation Diffie-Hellman ratchet
     * https://whispersystems.org/docs/specifications/doubleratchet/#diffie-hellman-ratchet
     *
     * @export
     * @class AsymmetricRatchet
     */
    export class AsymmetricRatchet {
        /**
         * Creates new ratchet for given identity from PreKeyBundle or PreKey messages
         *
         * @static
         * @param {Identity} identity
         * @param {(PreKeyBundleProtocol | PreKeyMessageProtocol)} protocol
         * @returns
         *
         * @memberOf AsymmetricRatchet
         */
        static create(identity: Identity, protocol: PreKeyBundleProtocol | PreKeyMessageProtocol): Promise<AsymmetricRatchet>;
        id: number;
        rootKey: HMACCryptoKey;
        identity: Identity;
        remoteIdentity: RemoteIdentity;
        remotePreKeyId?: number;
        remotePreKeySignedId: number;
        counter: number;
        currentStep: DHRatchetStep;
        currentRatchetKey: ECKeyPair;
        protected steps: DHRatchetStepStack;
        private constructor();
        /**
         * Verifies and decrypts data from SignedMessage
         *
         * @param {MessageSignedProtocol} protocol
         * @returns
         *
         * @memberOf AsymmetricRatchet
         */
        decrypt(protocol: MessageSignedProtocol): Promise<ArrayBuffer>;
        /**
         * Encrypts message
         *
         * @param {ArrayBuffer} message
         * @returns
         *
         * @memberOf AsymmetricRatchet
         */
        encrypt(message: ArrayBuffer): Promise<MessageSignedProtocol | PreKeyMessageProtocol>;
        /**
         * Generate new ratchet key
         *
         * @protected
         * @returns
         *
         * @memberOf AsymmetricRatchet
         */
        protected generateRatchetKey(): Promise<ECKeyPair>;
        /**
         * Creates new symmetric ratchet
         *
         * @protected
         * @param {ECDHPrivateKey} ourRatchetKey
         * @param {ECPublicKey} theirRatchetKey
         * @param {typeof ReceivingRatchet} ratchetClass
         * @returns {Promise<ReceivingRatchet>}
         *
         * @memberOf AsymmetricRatchet
         */
        protected createChain(ourRatchetKey: ECDHPrivateKey, theirRatchetKey: ECPublicKey, ratchetClass: typeof ReceivingRatchet): Promise<ReceivingRatchet>;
        protected createChain(ourRatchetKey: ECDHPrivateKey, theirRatchetKey: ECPublicKey, ratchetClass: typeof SendingRatchet): Promise<SendingRatchet>;
    }
    /**
     * Implementation of step of the Diffie-Hellman ratchet
     *
     * @export
     * @class DHRatchetStep
     */
    export class DHRatchetStep {
        /**
         * Remote client's ratchet key
         *
         * @type {ECPublicKey}
         * @memberOf DHRatchetStep
         */
        remoteRatchetKey?: ECPublicKey;
        /**
         * Sending chain
         *
         * @type {SendingRatchet}
         * @memberOf DHRatchetStep
         */
        sendingChain?: SendingRatchet;
        /**
         * Receiving chain
         *
         * @type {ReceivingRatchet}
         * @memberOf DHRatchetStep
         */
        receivingChain?: ReceivingRatchet;
    }
    /**
     * Implements collection of DHRatchetStep
     *
     * @export
     * @class DHRatchetStepStack
     * @extends {Stack<DHRatchetStep>}
     */
    export class DHRatchetStepStack extends Stack<DHRatchetStep> {
        /**
         * Returns DHRatchetStep by given remote client's ratchet key
         * @param {ECPublicKey} remoteRatchetKey remote client's ratchet key
         * @returns
         *
         * @memberOf DHRatchetStepStack
         */
        getStep(remoteRatchetKey: ECPublicKey): DHRatchetStep;
    }

    /**
     * Encrypt/Decrypt result for Symmetric ratchets
     *
     * @export
     * @interface CipherMessage
     */
    export interface CipherMessage {
        /**
         * Encrypted or decrypted message
         */
        cipherText: ArrayBuffer;
        /**
         * HMAC key for SignedMessage calculations
         */
        hmacKey: CryptoKey;
    }
    export abstract class SymmetricRatchet {
        counter: number;
        /**
         * Current symmetric ratchet key
         */
        rootKey: HMACCryptoKey;
        constructor(rootKey: CryptoKey);
        /**
         * calculates new keys by rootKey KDF_CK(ck)
         * https://whispersystems.org/docs/specifications/doubleratchet/#external-functions
         *
         * @protected
         * @param {CryptoKey} rootKey
         * @returns
         *
         * @memberOf SymmetricRatchet
         */
        protected calculateKey(rootKey: CryptoKey): Promise<SymmetricKDFResult>;
        /**
         * Move to next step of ratchet
         *
         * @protected
         * @returns
         *
         * @memberOf SymmetricRatchet
         */
        protected click(): Promise<ArrayBuffer>;
    }
    /**
     * Implementation of Sending chain
     *
     * @export
     * @class SendingRatchet
     * @extends {SymmetricRatchet}
     */
    export class SendingRatchet extends SymmetricRatchet {
        /**
         * Encrypts message
         *
         * @param {ArrayBuffer} message
         * @returns CipherMessage type
         *
         * @memberOf SendingRatchet
         */
        encrypt(message: ArrayBuffer): Promise<CipherMessage>;
    }
    export class ReceivingRatchet extends SymmetricRatchet {
        protected keys: ArrayBuffer[];
        decrypt(message: ArrayBuffer, counter: number): Promise<CipherMessage>;
        protected getKey(counter: number): Promise<ArrayBuffer>;
    }

}

export = DKeyRatchet;
export as namespace DKeyRatchet;
