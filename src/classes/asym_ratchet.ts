/**
 * 
 * 2key-ratchet
 * Copyright (c) 2016 Peculiar Ventures, Inc
 * Based on https://whispersystems.org/docs/specifications/doubleratchet/ and
 * https://whispersystems.org/docs/specifications/x3dh/ by Open Whisper Systems
 * 
 */

import { EventEmitter } from "events";
import { combine, Convert } from "pvtsutils";
import { INFO_RATCHET, INFO_TEXT, MAX_RATCHET_STACK_SIZE, SECRET_KEY_NAME } from "./const";
import { Curve, ECKeyPair, ECPublicKey, Secret } from "./crypto";
import { Identity } from "./data";
import { RemoteIdentity } from "./data/remote_identity";
import { MessageSignedProtocol, PreKeyBundleProtocol, PreKeyMessageProtocol } from "./protocol";
import { Stack } from "./stack";
import { ReceivingRatchet, SendingRatchet, SymmetricRatchet } from "./sym_ratchet";
import { IJsonReceivingRatchet, IJsonSymmetricRatchet } from "./sym_ratchet";
import { IJsonSerializable } from "./type";
import { ECDHPrivateKey, ECDHPublicKey, HMACCryptoKey } from "./type";

/**
 * Authentication. Calculates rootKey for DH ratchet
 * 
 * https://whispersystems.org/docs/specifications/x3dh/#sending-the-initial-message
 * 
 * @static
 * @param {boolean} flag Sets order for auth mechanism.
 * - If `true` then DH1 || DH2, otherwise DH2 || DH1
 * @param {Identity} IKA
 * @param {ECKeyPair} EKA
 * @param {RemoteIdentity} IKB Bob's identity key IKB
 * @param {ECPublicKey} SPKB Bob's signed prekey SPKB
 * @param {ECPublicKey} [OPKB] Bob's one-time prekey OPKB. Optionally
 *
 */
async function authenticate(flag: boolean, IKa: Identity, EKa: ECKeyPair, IKb: ECPublicKey, SPKb: ECPublicKey, OPKb?: ECPublicKey) {
    /**
     * DH1 = DH(IKa, SPKb)
     * DH2 = DH(EKa, IKb)
     * DH3 = DH(EKa, SPKb)
     * SK = KDF(DH1 || DH2 || DH3)
     */
    const DH1 = await Curve.deriveBytes(IKa.exchangeKey.privateKey, SPKb);
    const DH2 = await Curve.deriveBytes(EKa.privateKey, IKb);
    const DH3 = await Curve.deriveBytes(EKa.privateKey, SPKb);
    let DH4 = new ArrayBuffer(0);
    if (OPKb) {
        // DH4 = DH(EKA, OPKB)
        DH4 = await Curve.deriveBytes(EKa.privateKey, OPKb);
    }
    const DH = flag ? combine(DH1, DH2) : combine(DH2, DH1);
    const F = new Uint8Array(32).map(() => 0xff).buffer;
    const KM = combine(F, DH, DH3, DH4); // TODO: F || KM, where F = 0xFF * N
    const keys = await Secret.HKDF(KM, 1, void 0, INFO_TEXT);
    return await Secret.importHMAC(keys[0]);
}

export interface IJsonAsymmetricRatchet {
    remoteIdentity: string;
    ratchetKey: CryptoKeyPair;
    counter: number;
    rootKey: CryptoKey;
    steps: IJsonDHRatchetStep[];
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
    public static async create(identity: Identity, protocol: PreKeyBundleProtocol | PreKeyMessageProtocol) {
        let rootKey: HMACCryptoKey;
        const ratchet = new AsymmetricRatchet();

        if (protocol instanceof PreKeyBundleProtocol) {
            // PreKey Bundle

            // verify remote identity key
            if (!await protocol.identity.verify()) {
                throw new Error("Error: Remote client's identity key is invalid.");
            }

            // verify remote signed prekey
            if (!await protocol.preKeySigned.verify(protocol.identity.signingKey)) {
                throw new Error("Error: Remote client's signed prekey is invalid.");
            }

            ratchet.currentRatchetKey = await ratchet.generateRatchetKey();
            ratchet.currentStep.remoteRatchetKey = protocol.preKeySigned.key;
            ratchet.remoteIdentity = RemoteIdentity.fill(protocol.identity);
            ratchet.remoteIdentity.id = protocol.registrationId;
            ratchet.remotePreKeyId = protocol.preKey.id;
            ratchet.remotePreKeySignedId = protocol.preKeySigned.id;

            rootKey = await authenticate(
                true,
                identity, ratchet.currentRatchetKey,
                protocol.identity.exchangeKey, protocol.preKeySigned.key, protocol.preKey.key);
        } else {
            // PreKey Message

            // verify remote identity
            if (!await protocol.identity.verify()) {
                throw new Error("Error: Remote client's identity key is invalid.");
                // INFO: We can move THROW to verify function. Cause verification is critical.
            }

            // get signed prekey for identity
            const signedPreKey = identity.signedPreKeys[protocol.preKeySignedId];
            if (!signedPreKey) {
                throw new Error(`Error: PreKey with id ${protocol.preKeySignedId} not found`);
            }

            // get one-time prekey
            let preKey: ECKeyPair | undefined;
            if (protocol.preKeyId) {
                preKey = identity.preKeys[protocol.preKeyId];
            }

            ratchet.remoteIdentity = RemoteIdentity.fill(protocol.identity);
            ratchet.currentRatchetKey = signedPreKey;
            rootKey = await authenticate(
                false,
                identity, ratchet.currentRatchetKey,
                protocol.identity.exchangeKey, protocol.signedMessage.message.senderRatchetKey, preKey && preKey.publicKey);

        }
        // console.info(`${this.name}:Create Diffie-Hellman ratchet for ${identity.id}`);
        ratchet.identity = identity;
        ratchet.id = identity.id;
        ratchet.rootKey = rootKey;
        return ratchet;
    }

    public static async fromJSON(identity: Identity, remote: RemoteIdentity, obj: IJsonAsymmetricRatchet) {
        const res = new AsymmetricRatchet();
        res.identity = identity;
        res.remoteIdentity = remote;
        await res.fromJSON(obj);
        return res;
    }

    public id: number;
    public rootKey: HMACCryptoKey;
    public identity: Identity;
    public remoteIdentity: RemoteIdentity;
    public remotePreKeyId?: number;
    public remotePreKeySignedId: number;
    public counter = 0;
    public currentStep = new DHRatchetStep();
    public currentRatchetKey: ECKeyPair;
    protected steps = new DHRatchetStepStack(MAX_RATCHET_STACK_SIZE);
    protected promises: { [key: string]: Promise<any> } = {};

    protected constructor() {
        super();
    }

    public on(event: "update", listener: () => void): this;
    // public on(event: string | symbol, listener: Function): this;
    public on(event: string | symbol, listener: Function) {
        return super.on(event, listener);
    }

    public once(event: "update", listener: () => void): this;
    // public once(event: string | symbol, listener: Function): this;
    public once(event: string | symbol, listener: Function) {
        return super.once(event, listener);
    }

    /**
     * Verifies and decrypts data from SignedMessage
     *
     * @param {MessageSignedProtocol} protocol
     * @returns
     *
     * @memberOf AsymmetricRatchet
     */
    public async decrypt(protocol: MessageSignedProtocol) {
        // console.info(`${this.constructor.name}:Decrypts message`);
        return this.queuePromise("encrypt", async () => {
            const remoteRatchetKey = protocol.message.senderRatchetKey;
            const message = protocol.message;

            if (protocol.message.previousCounter < this.counter - MAX_RATCHET_STACK_SIZE) {
                throw new Error("Error: Too old message");
            }
            let step = this.steps.getStep(remoteRatchetKey);
            if (!step) {
                // We ve got new ratchet key, creating new ReceivingChain
                const ratchetStep = new DHRatchetStep();
                ratchetStep.remoteRatchetKey = remoteRatchetKey;
                this.steps.push(ratchetStep);
                this.currentStep = ratchetStep;
                step = ratchetStep;
            }

            if (!step.receivingChain) {
                // got 1 message for current ratchet step, have to create ReceiverRatchet
                step.receivingChain = await this.createChain(this.currentRatchetKey.privateKey, remoteRatchetKey, ReceivingRatchet);
            }

            const decryptedMessage = await step.receivingChain.decrypt(message.cipherText, message.counter);

            this.update();

            // verifying message signature
            protocol.senderKey = this.remoteIdentity.signingKey;
            protocol.receiverKey = this.identity.signingKey.publicKey;
            if (!await protocol.verify(decryptedMessage.hmacKey)) {
                throw new Error("Error: The Message did not successfully verify!");
            }

            return decryptedMessage.cipherText;
        });
    }

    /**
     * Encrypts message
     *
     * @param {ArrayBuffer} message
     * @returns
     *
     * @memberOf AsymmetricRatchet
     */
    public async encrypt(message: ArrayBuffer) {
        // console.info(`${this.constructor.name}:Encrypts message`);
        return this.queuePromise("encrypt", async () => {
            if (this.currentStep.receivingChain && !this.currentStep.sendingChain) {
                // close ratchet step
                this.counter++;
                this.currentRatchetKey = await this.generateRatchetKey();
            }
            // if false then no incoming message with new ratchet key, using old DH ratchet
            if (!this.currentStep.sendingChain) {
                this.currentStep.sendingChain = await this.createChain(this.currentRatchetKey.privateKey, this.currentStep.remoteRatchetKey, SendingRatchet);
            }

            const encryptedMessage = await this.currentStep.sendingChain.encrypt(message);

            this.update();

            let preKeyMessage: PreKeyMessageProtocol | undefined;
            if (this.steps.length === 0 &&
                !this.currentStep.receivingChain &&
                this.currentStep.sendingChain.counter === 1
            ) {
                // we send first message, MUST be PreKey message, otherwise SignedMessage
                preKeyMessage = new PreKeyMessageProtocol();
                preKeyMessage.registrationId = this.identity.id;
                preKeyMessage.preKeyId = this.remotePreKeyId;
                preKeyMessage.preKeySignedId = this.remotePreKeySignedId;
                preKeyMessage.baseKey = this.currentRatchetKey.publicKey;
                await preKeyMessage.identity.fill(this.identity);
            }

            const signedMessage = new MessageSignedProtocol();
            signedMessage.receiverKey = this.remoteIdentity.signingKey;
            signedMessage.senderKey = this.identity.signingKey.publicKey;
            // message
            signedMessage.message.cipherText = encryptedMessage.cipherText;
            signedMessage.message.counter = this.currentStep.sendingChain.counter - 1;
            signedMessage.message.previousCounter = this.counter;
            signedMessage.message.senderRatchetKey = this.currentRatchetKey.publicKey;
            await signedMessage.sign(encryptedMessage.hmacKey);

            if (preKeyMessage) {
                preKeyMessage.signedMessage = signedMessage;
                return preKeyMessage;
            } else {
                return signedMessage;
            }
        });
    }

    public async hasRatchetKey(key: CryptoKey | ECPublicKey) {
        let ecKey: ECPublicKey;
        if (!(key instanceof ECPublicKey)) {
            ecKey = await ECPublicKey.create(key);
        } else {
            ecKey = key;
        }
        for (const item of this.steps.items) {
            if (await item.remoteRatchetKey.isEqual(ecKey)) {
                return true;
            }
        }
        return false;
    }

    public async toJSON() {
        return {
            remoteIdentity: await this.remoteIdentity.signingKey.thumbprint(),
            ratchetKey: await Curve.ecKeyPairToJson(this.currentRatchetKey),
            counter: this.counter,
            rootKey: this.rootKey,
            steps: await this.steps.toJSON(),
        } as IJsonAsymmetricRatchet;
    }

    public async fromJSON(obj: IJsonAsymmetricRatchet) {
        this.currentRatchetKey = await Curve.ecKeyPairFromJson(obj.ratchetKey);
        this.counter = obj.counter;
        this.rootKey = obj.rootKey;

        for (const step of obj.steps) {
            this.currentStep = await DHRatchetStep.fromJSON(step);
            this.steps.push(this.currentStep);
        }
    }

    protected update() {
        this.emit("update");
    }

    /**
     * Generate new ratchet key
     *
     * @protected
     * @returns
     *
     * @memberOf AsymmetricRatchet
     */
    protected generateRatchetKey() {
        return Curve.generateKeyPair("ECDH");
    }

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
    protected async createChain(ourRatchetKey: ECDHPrivateKey, theirRatchetKey: ECPublicKey, ratchetClass: typeof ReceivingRatchet): Promise<ReceivingRatchet>;
    protected async createChain(ourRatchetKey: ECDHPrivateKey, theirRatchetKey: ECPublicKey, ratchetClass: typeof SendingRatchet): Promise<SendingRatchet>;
    protected async createChain(ourRatchetKey: ECDHPrivateKey, theirRatchetKey: ECPublicKey, ratchetClass: typeof ReceivingRatchet | typeof SendingRatchet) {
        // console.info(`${this.constructor.name}:${this.id}:Creating new ${ratchetClass.name}`);
        const derivedBytes = await Curve.deriveBytes(ourRatchetKey, theirRatchetKey);
        const keys = await Secret.HKDF(derivedBytes, 2, this.rootKey, INFO_RATCHET);
        const rootKey = await Secret.importHMAC(keys[0]);
        const chainKey = await Secret.importHMAC(keys[1]);
        const chain = new ratchetClass(chainKey);
        this.rootKey = rootKey; // update rootKey
        return chain;
    }

    protected queuePromise<T>(key: string, fn: () => Promise<T>): Promise<T> {
        const prev = this.promises[key] || Promise.resolve();
        const cur = this.promises[key] = prev.then(fn, fn);
        cur.then(() => {
            if (this.promises[key] === cur) {
                delete this.promises[key];
            }
        });
        return cur;
    }

}

export interface IJsonDHRatchetStep {
    remoteRatchetKey?: CryptoKey;
    sendingChain?: IJsonSymmetricRatchet;
    receivingChain?: IJsonReceivingRatchet;
}

/**
 * Implementation of step of the Diffie-Hellman ratchet
 *
 * @export
 * @class DHRatchetStep
 */
export class DHRatchetStep implements IJsonSerializable {

    public static async fromJSON(obj: IJsonDHRatchetStep) {
        const res = new this();
        await res.fromJSON(obj);
        return res;
    }

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

    public async toJSON() {
        const res: IJsonDHRatchetStep = {};
        if (this.remoteRatchetKey) {
            res.remoteRatchetKey = this.remoteRatchetKey.key;
        }
        if (this.sendingChain) {
            res.sendingChain = await this.sendingChain.toJSON();
        }
        if (this.receivingChain) {
            res.receivingChain = await this.receivingChain.toJSON();
        }
        return res;
    }

    public async fromJSON(obj: IJsonDHRatchetStep) {
        if (obj.remoteRatchetKey) {
            this.remoteRatchetKey = await ECPublicKey.create(obj.remoteRatchetKey);
        }
        if (obj.sendingChain) {
            this.sendingChain = await SendingRatchet.fromJSON(obj.sendingChain);
        }
        if (obj.receivingChain) {
            this.receivingChain = await ReceivingRatchet.fromJSON(obj.receivingChain);
        }
    }

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
    public getStep(remoteRatchetKey: ECPublicKey) {
        let found: DHRatchetStep = void 0;
        this.items.some((step) => {
            if (step.remoteRatchetKey === remoteRatchetKey) {
                found = step;
            }
            return !!found;
        });
        return found;
    }

}
