import { EventEmitter } from "events";
import { ObjectProto } from "tsprotobuf";

declare namespace DKeyRatchet {

    // types

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

    export interface ISymmetricKDFResult {
        cipher: ArrayBuffer;
        rootKey: CryptoKey;
    }

    export interface IJsonSerializable {
        toJSON(): Promise<any>;
        fromJSON(obj: any): Promise<void>;
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
        public static create(publicKey: CryptoKey): Promise<ECPublicKey>;
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
        public static importKey(bytes: ArrayBuffer, type: ECKeyType): Promise<ECPublicKey>;
        /**
         * Identity of ECPublicKey
         * HEX string of thumbprint of EC key
         *
         * @type {string}
         * @memberOf ECPublicKey
         */
        public id: string;
        /**
         * Crypto key
         *
         * @type {CryptoKey}
         * @memberOf ECPublicKey
         */
        public key: CryptoKey;
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
        public serialize(): ArrayBuffer;
        /**
         * Returns SHA-256 digest of key
         *
         * @returns
         *
         * @memberOf ECPublicKey
         */
        public thumbprint(): Promise<string>;
        /**
         * Returns `true` if current is equal to given parameter
         *
         * @param {*} other
         * @returns
         *
         * @memberOf ECPublicKey
         */
        public isEqual(other: any): Promise<boolean>;
    }

    export interface IECKeyPair {
        privateKey: CryptoKey;
        publicKey: ECPublicKey;
    }

    export class Curve {
        public static NAMED_CURVE: string;
        public static DIGEST_ALGORITHM: string;
        /**
         * Generates new EC key pair
         *
         * @static
         * @param {ECKeyType} type type of EC key. ECDSA | ECDH
         * @returns
         *
         * @memberOf Curve
         */
        public static generateKeyPair(type: ECKeyType): Promise<IECKeyPair>;
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
        public static deriveBytes(privateKey: ECDHPrivateKey, publicKey: ECPublicKey): PromiseLike<ArrayBuffer>;
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
        public static verify(
            signingKey: ECPublicKey,
            message: ArrayBuffer,
            signature: ArrayBuffer,
        ): PromiseLike<boolean>;
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
        public static sign(signingKey: ECDHPrivateKey, message: ArrayBuffer): Promise<ArrayBuffer>;
    }

    export class Secret {
        /**
         * Returns ArrayBuffer of random bytes
         *
         * @static
         * @param {number} size size of output buffer
         * @returns
         *
         * @memberOf Secret
         */
        public static randomBytes(size: number): ArrayBuffer;
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
        public static digest(alg: string, message: ArrayBuffer): PromiseLike<ArrayBuffer>;
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
        public static encrypt(key: CryptoKey, data: ArrayBuffer, iv: ArrayBuffer): PromiseLike<ArrayBuffer>;
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
        public static decrypt(key: CryptoKey, data: ArrayBuffer, iv: ArrayBuffer): PromiseLike<ArrayBuffer>;
        /**
         * Creates HMAC key from raw data
         *
         * @static
         * @param {ArrayBuffer} raw
         * @returns
         *
         * @memberOf Secret
         */
        public static importHMAC(raw: ArrayBuffer): PromiseLike<CryptoKey>;
        /**
         * Creates AES key from raw data
         *
         * @static
         * @param {ArrayBuffer} raw
         * @returns
         *
         * @memberOf Secret
         */
        public static importAES(raw: ArrayBuffer): PromiseLike<CryptoKey>;
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
        public static sign(key: CryptoKey, data: ArrayBuffer): Promise<ArrayBuffer>;
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
        public static HKDF(
            IKM: ArrayBuffer,
            keysCount?: number,
            salt?: HMACCryptoKey,
            info?: ArrayBuffer,
        ): Promise<ArrayBuffer[]>;
    }

    // data

    export class Address {
        protected static readonly SPLITTER: string;
        public name: string;
        public id: number;
        constructor(name: string, id: number);
        public toString(): string;
    }

    export interface IJsonIdentity {
        id: number;
        signingKey: CryptoKeyPair;
        exchangeKey: CryptoKeyPair;
        preKeys: CryptoKeyPair[];
        signedPreKeys: CryptoKeyPair[];
        createdAt: string;
    }

    export class Identity implements IJsonSerializable {
        public static fromJSON(obj: IJsonIdentity): Promise<Identity>;
        public static create(id: number, signedPreKeyAmount?: number, preKeyAmount?: number): Promise<Identity>;
        public id: number;
        public signingKey: IECKeyPair;
        public exchangeKey: IECKeyPair;
        public preKeys: IECKeyPair[];
        public signedPreKeys: IECKeyPair[];
        public createdAt: Date;
        protected constructor(id: number, signingKey: IECKeyPair, exchangeKey: IECKeyPair);
        public toJSON(): Promise<IJsonIdentity>;
        public fromJSON(obj: IJsonIdentity): Promise<void>;
    }

    export interface IJsonRemoteIdentity {
        id: number;
        /**
         * Thumbprint of signing key
         *
         * @type {string}
         * @memberOf IJsonRemoteIdentity
         */
        thumbprint: string;
        signingKey: CryptoKey;
        exchangeKey: CryptoKey;
        signature: ArrayBuffer;
        createdAt: string;
    }

    export class RemoteIdentity implements IJsonSerializable {
        public static fill(protocol: IdentityProtocol): RemoteIdentity;
        public static fromJSON(obj: IJsonRemoteIdentity): Promise<RemoteIdentity>;
        public id: number;
        public signingKey: ECPublicKey;
        public exchangeKey: ECPublicKey;
        public signature: ArrayBuffer;
        public createdAt: Date;
        public fill(protocol: IdentityProtocol): void;
        public verify(): PromiseLike<boolean>;
        public toJSON(): Promise<IJsonRemoteIdentity>;
        public fromJSON(obj: IJsonRemoteIdentity): Promise<void>;
    }

    // protocol

    export abstract class BaseProtocol extends ObjectProto {
        public version: number;
    }

    export class IdentityProtocol extends BaseProtocol {
        public static fill(identity: Identity): Promise<IdentityProtocol>;
        public signingKey: ECPublicKey;
        public exchangeKey: ECPublicKey;
        public signature: ArrayBuffer;
        public createdAt: Date;
        public sign(key: CryptoKey): Promise<void>;
        public verify(): Promise<boolean>;
        public fill(identity: Identity): Promise<void>;
    }

    export class MessageProtocol extends BaseProtocol {
        public senderRatchetKey: ECPublicKey;
        public counter: number;
        public previousCounter: number;
        public cipherText: ArrayBuffer;
    }

    export class MessageSignedProtocol extends BaseProtocol {
        public receiverKey: ECPublicKey;
        public senderKey: ECPublicKey;
        public message: MessageProtocol;
        protected signature: ArrayBuffer;
        public sign(hmacKey: CryptoKey): Promise<void>;
        public verify(hmacKey: CryptoKey): Promise<boolean>;
        protected getSignedRaw(): Promise<ArrayBuffer>;
        protected signHMAC(macKey: CryptoKey): Promise<ArrayBuffer>;
    }

    export class PreKeyMessageProtocol extends BaseProtocol {
        public registrationId: number;
        public preKeyId: number;
        public preKeySignedId: number;
        public baseKey: ECPublicKey;
        public identity: IdentityProtocol;
        public signedMessage: MessageSignedProtocol;
    }

    export class PreKeyProtocol extends BaseProtocol {
        public id: number;
        public key: ECPublicKey;
    }

    export class PreKeySignedProtocol extends PreKeyProtocol {
        public signature: ArrayBuffer;
        public sign(key: CryptoKey): Promise<void>;
        public verify(key: ECPublicKey): PromiseLike<boolean>;
    }

    export class PreKeyBundleProtocol extends BaseProtocol {
        public registrationId: number;
        public identity: IdentityProtocol;
        public preKey: PreKeyProtocol;
        public preKeySigned: PreKeySignedProtocol;
    }

    // core

    export class Stack<T> {
        public items: T[];
        public readonly length: number;
        public readonly latest: T;
        protected maxSize: number;
        public constructor(maxSize?: number);
        public push(item: T): void;
    }

    export class AssocStorage<T> {
        public readonly length: number;
        protected items: {
            [key: string]: T;
        };
        public save(key: string, value: T): void;
        public load(key: string): T;
        public remove(key: string): void;
        public clear(): void;
    }

    export interface IJsonAsymmetricRatchet {
        remoteIdentity: string;
        ratchetKey: CryptoKeyPair;
        counter: number;
        rootKey: CryptoKey;
        steps: IJsonDHRatchetStep[];
    }

    export interface IJsonDHRatchetStep {
        remoteRatchetKey?: CryptoKey;
        sendingChain?: IJsonSymmetricRatchet;
        receivingChain?: IJsonReceivingRatchet;
    }

    export interface IJsonSymmetricRatchet {
        counter: number;
        rootKey: CryptoKey;
    }

    export interface IJsonReceivingRatchet extends IJsonSymmetricRatchet {
        keys: ArrayBuffer[];
    }

    /**
     * Implementation Diffie-Hellman ratchet
     * https://whispersystems.org/docs/specifications/doubleratchet/#diffie-hellman-ratchet
     *
     * @export
     * @class AsymmetricRatchet
     */
    export class AsymmetricRatchet extends EventEmitter implements IJsonSerializable {
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
        public static create(
            identity: Identity,
            protocol: PreKeyBundleProtocol | PreKeyMessageProtocol,
        ): Promise<AsymmetricRatchet>;
        public static fromJSON(
            identity: Identity,
            remote: RemoteIdentity,
            obj: IJsonAsymmetricRatchet,
        ): Promise<AsymmetricRatchet>;
        public id: number;
        public rootKey: HMACCryptoKey;
        public identity: Identity;
        public remoteIdentity: RemoteIdentity;
        public remotePreKeyId?: number;
        public remotePreKeySignedId: number;
        public counter: number;
        public currentStep: DHRatchetStep;
        public currentRatchetKey: IECKeyPair;
        protected steps: DHRatchetStepStack;
        protected constructor();

        public on(event: "update", listener: () => void): this;
        public once(event: "update", listener: () => void): this;

        /**
         * Verifies and decrypts data from SignedMessage
         *
         * @param {MessageSignedProtocol} protocol
         * @returns
         *
         * @memberOf AsymmetricRatchet
         */
        public decrypt(protocol: MessageSignedProtocol): Promise<ArrayBuffer>;
        /**
         * Encrypts message
         *
         * @param {ArrayBuffer} message
         * @returns
         *
         * @memberOf AsymmetricRatchet
         */
        public encrypt(message: ArrayBuffer): Promise<MessageSignedProtocol | PreKeyMessageProtocol>;

        public toJSON(): Promise<IJsonAsymmetricRatchet>;
        public fromJSON(obj: IJsonAsymmetricRatchet): Promise<void>;

        public hasRatchetKey(key: CryptoKey | ECPublicKey): Promise<boolean>;
        /**
         * Generate new ratchet key
         *
         * @protected
         * @returns
         *
         * @memberOf AsymmetricRatchet
         */
        protected generateRatchetKey(): Promise<IECKeyPair>;
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
        // tslint:disable-next-line:max-line-length
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
        public remoteRatchetKey?: ECPublicKey;
        /**
         * Sending chain
         *
         * @type {SendingRatchet}
         * @memberOf DHRatchetStep
         */
        public sendingChain?: SendingRatchet;
        /**
         * Receiving chain
         *
         * @type {ReceivingRatchet}
         * @memberOf DHRatchetStep
         */
        public receivingChain?: ReceivingRatchet;
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
        public getStep(remoteRatchetKey: ECPublicKey): DHRatchetStep;
    }

    /**
     * Encrypt/Decrypt result for Symmetric ratchets
     *
     * @export
     * @interface ICipherMessage
     */
    export interface ICipherMessage {
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
        public counter: number;
        /**
         * Current symmetric ratchet key
         */
        public rootKey: HMACCryptoKey;
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
        protected calculateKey(rootKey: CryptoKey): Promise<ISymmetricKDFResult>;
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
         * @returns ICipherMessage type
         *
         * @memberOf SendingRatchet
         */
        public encrypt(message: ArrayBuffer): Promise<ICipherMessage>;
    }
    export class ReceivingRatchet extends SymmetricRatchet {
        protected keys: ArrayBuffer[];
        public decrypt(message: ArrayBuffer, counter: number): Promise<ICipherMessage>;
        protected getKey(counter: number): Promise<ArrayBuffer>;
    }

    // Crypto engine

    /**
     * Crypto engine structure
     *
     * @export
     * @interface ICryptoEngine
     */
    export interface ICryptoEngine {
        name: string;
        crypto: Crypto;
    }

    /**
     * Sets crypto engine
     *
     * @export
     * @param {string} name     Name of engine
     * @param {Crypto} crypto   WebCrypto implementation
     */
    export function setEngine(name: string, crypto: Crypto): void;

    /**
     * Returns crypto engine
     * It throws exception if engine is empty.
     *
     * @export
     * @returns {ICryptoEngine}
     */
    export function getEngine(): ICryptoEngine;

}

export = DKeyRatchet;
export as namespace DKeyRatchet;
