import { assert } from "chai";
import { Convert } from "pvtsutils";
import { AsymmetricRatchet } from "../classes/asym_ratchet";
import { Secret } from "../classes/crypto";
import { Identity } from "../classes/data/identity";
import { MessageSignedProtocol, PreKeyBundleProtocol, PreKeyMessageProtocol } from "../classes/protocol";
import { ReceivingRatchet, SendingRatchet } from "../classes/sym_ratchet";
import { createIdentity, createPreKeyBundle } from "./helper";

const PREKEY_BUNDLE = "0001080112e40100010a4104f3a7e8df14450b795f3ce9b6ea154b4db185928d8522fa4d2356d6076d8ff26a8d67365d9d4482d9c84938f1b6da2199b29e093859bff9064947518a40ac5839124104add99a66461222125729e8953947c7ac5dc9e383978d8838c74c0ca714e3703c1bbfb1c81d43305541a6497dedb2db1aee459900d81fbd2ba00352b2e52009ef1a402b39a7dfdcf59abcffd0d5326e31f817e9337a5e391076e8a4e03f7cb1d471b50e1bcbdd57f07f57dd1a0fb62cfc9c7cae83ef57a2955e801abc82dad2cd0f3a2218323031372d30382d31375431353a31343a34392e3234365a2289010001080012410437ef6e0ccbe4cafb437fc72e242b9af20a4e61216aabb68b26ad84d46da6997c16b767fa522fb7b0642aa2b7a6119ca144b6f1838155bee79331bdf743b3a4fb1a40aed97100b21c76b8e3fde4573fb0d7ba528bc81cb280797d84b23f3b4fb97e0a7a9f3efa95f84b9321edd474ed06c7fd038c25f93845b882c22ef84405b0d3fa";

const PREKEY_BUNDLE_WRONG_IDENTITY_SIGNATURE = "0001080112e40100010a4104f3a7e8df14450b795f3ce9b6ea154b4db185928d8522fa4d2356d6076d8ff26a8d67365d9d4482d9c84938f1b6da2199b29e093859bff9064947518a40ac5839124104add99a66461222125729e8953947c7ac5dc9e383978d8838c74c0ca714e3703c1bbfb1c81d43305541a6497dedb2db1aee459900d81fbd2ba00352b2e52009ef1a402b39a7dfdcf59abcffd0d5326e31f817e9337a5e391076e8a4e03f7cb1d471b50e1bcbdd57f07f57dd1a0fb62cfc9c7cae83ef57a2955e801abc82dad2cd0f3a2218323031372d30382d31375431353a31343a34392e3234365a2289010001080012410437ef6e0ccbe4cafb437fc72e242b9af20a4e61216aabb68b26ad84d46da6997c16b767fa522fb7b0642aa2b7a6119ca144b6f1838155bee79331bdf743b3a4fb1a40aed97100b21c76b8e3fde4573fb0d7ba528bc81cb280797d84b23f3b4fb97e0a7a9f3efa95f84b9321edd474ed06c7fd038c25f93845b882c22ef84405b0d3fa";

const PREKEY_BUNDLE_WRONG_PRE_KEY_SIGNATURE = "0001080112e40100010a4104f3a7e8df14450b795f3ce9b6ea154b4db185928d8522fa4d2356d6076d8ff26a8d67365d9d4482d9c84938f1b6da2199b29e093859bff9064947518a40ac5839124104add99a66461222125729e8953947c7ac5dc9e383978d8838c74c0ca714e3703c1bbfb1c81d43305541a6497dedb2db1aee459900d81fbd2ba00352b2e52009ef1a402b39a7dfdcf59abcffd0d5326e31f817e9337a5e391076e8a4e03f7cb1d471b50e1bcbdd57f07f57dd1a0fb62cfc9c7cae83ef57a2955e801abc82dad2cd0f3a2218323031372d30382d31375431353a31343a34392e3234365a2289010001080012410437ef6e0ccbe4cafb437fc72e242b9af20a4e61216aabb68b26ad84d46da6997c16b767fa522fb7b0642aa2b7a6119ca144b6f1838155bee79331bdf743b3a4fb1a40aed97100b21c76b8e3fde4573fb0d7ba528bc81cb280797d84b23f3b4fb97e0a7a9f3efa95f84b9321edd474ed06c7fd038c25f93845b882c22ef84405b0d3fa";

function toHex(bytes: ArrayBuffer) {
    return new Buffer(bytes).toString("hex");
}

function isEqual(buf1: ArrayBuffer, buf2: ArrayBuffer) {
    return toHex(buf1) === toHex(buf2);
}

context("Ratchet", () => {

    let rootKey: CryptoKey;
    const message = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8, 9, 0]).buffer;
    const encMessage: ArrayBuffer[] = [];

    before((done) => {
        const rnd = Secret.randomBytes(32);
        Secret.importHMAC(rnd)
            .then((key) => {
                rootKey = key;
            })
            .then(done, done);
    });

    it("SendingRatchet", (done) => {
        async function Test() {
            const sender = new SendingRatchet(rootKey);
            assert.equal(sender.counter, 0);

            encMessage.push((await sender.encrypt(message)).cipherText);
            encMessage.push((await sender.encrypt(message)).cipherText);
            encMessage.push((await sender.encrypt(message)).cipherText);
            encMessage.push((await sender.encrypt(message)).cipherText);

            assert.equal(sender.counter, 4);
            assert.equal(isEqual(encMessage[0], encMessage[1]), false);
            assert.equal(isEqual(encMessage[1], encMessage[2]), false);
            assert.equal(isEqual(encMessage[2], encMessage[3]), false);
        }
        Test().then(done, done);

    });

    context("ReceivingRatchet", () => {

        it("step by step", (done) => {
            async function Test() {
                const sender = new ReceivingRatchet(rootKey);
                assert.equal(sender.counter, 0);

                const msg: ArrayBuffer[] = [];

                msg.push((await sender.decrypt(encMessage[0], 0)).cipherText);
                msg.push((await sender.decrypt(encMessage[1], 1)).cipherText);
                msg.push((await sender.decrypt(encMessage[2], 2)).cipherText);
                msg.push((await sender.decrypt(encMessage[3], 3)).cipherText);

                assert.equal(sender.counter, 4);
                assert.equal(isEqual(msg[0], message), true);
                assert.equal(isEqual(msg[1], message), true);
                assert.equal(isEqual(msg[2], message), true);
                assert.equal(isEqual(msg[3], message), true);
            }
            Test().then(done, done);

        });

        it("get message with custom counter", (done) => {
            async function Test() {
                const sender = new ReceivingRatchet(rootKey);
                assert.equal(sender.counter, 0);

                const msg = (await sender.decrypt(encMessage[3], 3)).cipherText;

                assert.equal(sender.counter, 4);
                assert.equal(isEqual(msg, message), true);
            }
            Test().then(done, done);
        });

        it("random counter", (done) => {
            async function Test() {
                const sender = new ReceivingRatchet(rootKey);
                assert.equal(sender.counter, 0);

                const msg: ArrayBuffer[] = [];

                msg.push((await sender.decrypt(encMessage[2], 2)).cipherText);
                msg.push((await sender.decrypt(encMessage[0], 0)).cipherText);
                msg.push((await sender.decrypt(encMessage[3], 3)).cipherText);
                msg.push((await sender.decrypt(encMessage[1], 1)).cipherText);

                assert.equal(sender.counter, 4);
                assert.equal(isEqual(msg[0], message), true);
                assert.equal(isEqual(msg[1], message), true);
                assert.equal(isEqual(msg[2], message), true);
                assert.equal(isEqual(msg[3], message), true);
            }
            Test().then(done, done);
        });

    });

    context("asym ratchet", () => {

        context("create", () => {

            context("from PreKeyBundle", () => {
                it("without one-time PreKey", (done) => {

                    async function Test() {
                        const AliceID = await createIdentity(1);
                        const AliceBundle = await createPreKeyBundle(AliceID);

                        const BobID = await createIdentity(2);
                        const BobRatchet = await AsymmetricRatchet.create(BobID, AliceBundle);

                        // TODO: Check ratchet data
                        const raw = await AliceBundle.exportProto();
                    }

                    Test().then(done, done);
                });

                it("with one-time PreKey", (done) => {
                    async function Test() {
                        const AliceID = await createIdentity(1);
                        const AliceBundle = await createPreKeyBundle(AliceID);
                        AliceBundle.preKey.id = 2;
                        AliceBundle.preKey.key = AliceBundle.preKeySigned.key;

                        const BobID = await createIdentity(2);
                        const BobRatchet = await AsymmetricRatchet.create(BobID, AliceBundle);

                        // TODO: Check ratchet data
                        const raw = await AliceBundle.exportProto();
                    }

                    Test().then(done, done);
                });
            });

            it("form PreKeyBundle and PreKeyMessage", (done) => {
                async function Test() {
                    const AliceID = await createIdentity(1);
                    const BobID = await createIdentity(2);
                    const AlicePreKeyBundle = await createPreKeyBundle(AliceID);
                    const messageText = "Hello world!!";

                    const BobRatchet = await AsymmetricRatchet.create(BobID, AlicePreKeyBundle);
                    const BobMessage1 = await BobRatchet.encrypt(Convert.FromUtf8String(messageText));
                    const BobMessage2 = await BobRatchet.encrypt(Convert.FromUtf8String(messageText));

                    // Only first message mast be PreKeyMessage
                    assert.isTrue(BobMessage1 instanceof PreKeyMessageProtocol);
                    assert.isTrue(BobMessage2 instanceof MessageSignedProtocol);

                    const AliceRatchet = await AsymmetricRatchet.create(AliceID, BobMessage1 as PreKeyMessageProtocol);

                    let decrypted = await AliceRatchet.decrypt((BobMessage1 as PreKeyMessageProtocol).signedMessage);
                    assert.equal(messageText, Convert.ToUtf8String(decrypted));

                    decrypted = await AliceRatchet.decrypt((BobMessage2 as MessageSignedProtocol));
                    assert.equal(messageText, Convert.ToUtf8String(decrypted));
                }
                Test()
                    .then(done, done);
            });

            context("wrong incoming PreKeyBundle data", () => {
                [{ name: "identity signature", raw: PREKEY_BUNDLE_WRONG_IDENTITY_SIGNATURE }, { name: "prekey signature", raw: PREKEY_BUNDLE_WRONG_PRE_KEY_SIGNATURE }]
                    .forEach((item) => {
                        it(item.name, (done) => {
                            async function Test() {

                                const buf = Convert.FromHex(item.raw);
                                const bundle = await PreKeyBundleProtocol.importProto(buf);
                                const identity = await createIdentity(2);

                                try {
                                    await AsymmetricRatchet.create(identity, bundle);
                                    assert.isTrue(false, "Must be error");
                                } catch (err) {
                                    // console.log(err.message);
                                }
                            }
                            Test().then(done, done);
                        });
                    });
            });

        });

    });

});
