import { assert } from "chai";
import { Convert } from "pvtsutils";
import { AsymmetricRatchet } from "../classes/asym_ratchet";
import { Secret } from "../classes/crypto";
import { Identity } from "../classes/data/identity";
import { PreKey } from "../classes/data/pre_key";
import { MessageSignedProtocol, PreKeyBundleProtocol, PreKeyMessageProtocol } from "../classes/protocol";
import { ReceivingRatchet, SendingRatchet } from "../classes/sym_ratchet";
import { createIdentity, createPreKeyBundle } from "./helper";

const PREKEY_BUNDLE = "0001080112c80100010a407d36fdb6ca56228dc9f0f5d95c1b2208bc170689ae30591d4f3394d123ddc399e06ff32694138f2fa120856bf26bc2330c44c3281b98a43721c66a8d59f672d412406fd1dd2fb4888007747c5bb8d8c4f137c48f829c130b6f3e4121ea8a5e84d604233f6e358922296eb8a9cfd1cdf26589aaa2d26dd327c91058e09a6256859e171a409b56a6e41227737dc73def7cc42d5e436050bd5dcce2059f1ca597669be70b8b70a610835d7e7048f7857d0812da1fa31c3dd7540b7192b44902cab21fdab14b1a002288010001080112401e3c3a63c6c16fc17b13206c3dffd1a88f6d878ab5e89651fc81acc8da29903b985379d4b10f0c7c7b15d7f29e6bc81aab1ce1f92a2fc5751a10ed7ee286fc041a4063f2678382893923f0f273bfc9cabb4eb1c6ce49416d7b04a2fe1f064d472b0ec3dc2a703da56e27176386c2a6ce73c09a08f588bcccc73968cf53356ad7e275";

const PREKEY_BUNDLE_WRONG_IDENTITY_SIGNATURE = "0001080112c80100010a407d36fdb6ca56228dc9f0f5d95c1b2208bc170689ae30591d4f3394d123ddc399e06ff32694138f2fa120856bf26bc2330c44c3281b98a43721c66a8d59f672d412406fd1dd2fb4888007747c5bb8d8c4f137c48f829c130b6f3e4121ea8a5e84d604233f6e358922296eb8a9cfd1cdf26589aaa2d26dd327c91058e09a6256859e171a409b56a6e41227737dc73def7cc4205e436050bd5dcce2059f1ca597669be70b8b70a610835d7e7048f7857d0812da1fa31c3dd7540b7192b44902cab21fdab14b1a002288010001080112401e3c3a63c6c16fc17b13206c3dffd1a88f6d878ab5e89651fc81acc8da29903b985379d4b10f0c7c7b15d7f29e6bc81aab1ce1f92a2fc5751a10ed7ee286fc041a4063f2678382893923f0f273bfc9cabb4eb1c6ce49416d7b04a2fe1f064d472b0ec3dc2a703da56e27176386c2a6ce73c09a08f588bcccc73968cf53356ad7e275";

const PREKEY_BUNDLE_WRONG_PRE_KEY_SIGNATURE = "0001080112c80100010a40b1dca43fa2a920dd8882a3e4d5f2f8876e32bcc62d63082e85e1b2f87074772206641f7fdd1fea216bd279cb602351e0280f999a72c54d2d40ca192875cb4fe41240cbc78e1e0af61c1966e8a604bb55fa6468f96f9b3f32e883b9d49e3d8a9f5d43284aacb0cfbecf6db6d664a504c975e870a2aa20bc3d8b07eb627862c5362b661a40fd97642ea246beb1e73e3aede401e2fb6010f799e4791524a1dd918cf84f9a2d3d1448af677a29b8fd96449577e3f3264cec06ac7b2f83a9af944a13c8d9efcf228801000108011240ab2c101850cfb9a31127f26a4fd139ba2de720b6d2043721b10a306f69fb64a5d9dba92130e9236f35cb6c66e89ec25b9662170b2f5e82528e57b08fe92ccf7a1a409814ad399b735642f36bc2f22bf297f31e48e1fd6ab2a965398188e090aaa1300419169d0ec692fa21557db58ba3701ddc5cfc74c66539cdb28f8d8dbddbc07c";

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
