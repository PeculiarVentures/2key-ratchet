import { assert } from "chai";
import { Convert, isEqual } from "pvtsutils";
import { Identity } from "../classes/data";
import { IdentityProtocol, MessageSignedProtocol, PreKeyBundleProtocol } from "../classes/protocol";
import { PreKeySignedProtocol } from "../classes/protocol/prekey_signed";
import { createIdentity, createPreKeyBundle } from "./helper";

context("Protocol", () => {

    context("IdentityProtocol", () => {

        it("create", (done) => {
            Promise.resolve()
                .then(() => {
                    return createIdentity(1);
                })
                .then((res) => {
                    return IdentityProtocol.fill(res);
                })
                .then((identity) => {
                    assert.isTrue(!!identity.signingKey);
                    assert.isTrue(!!identity.exchangeKey);
                    assert.equal(identity.signature.byteLength, 64);
                })
                .then(done, done);
        });

        it("import/export", (done) => {
            let identity: IdentityProtocol;
            Promise.resolve()
                .then(() => {
                    return createIdentity(1);
                })
                .then((res) => {
                    return IdentityProtocol.fill(res);
                })
                .then((res) => {
                    identity = res;
                    return identity.exportProto();
                })
                .then((res) => {
                    return IdentityProtocol.importProto(res);
                })
                .then((res) => {
                    assert.equal(identity.signingKey.id, res.signingKey.id);
                    assert.equal(identity.exchangeKey.id, res.exchangeKey.id);
                    assert.isTrue(isEqual(identity.signature, res.signature));
                })
                .then(done, done);
        });

        it("verify", (done) => {
            let identity: IdentityProtocol;
            Promise.resolve()
                .then(() => {
                    return createIdentity(1);
                })
                .then((res) => {
                    return IdentityProtocol.fill(res);
                })
                .then((res) => {
                    identity = res;
                    return identity.verify();
                })
                .then((res) => {
                    assert.isTrue(res);

                    // break signature
                    const buf = new Uint8Array(identity.signature);
                    buf[3] = buf[3] + 1;
                    return identity.verify();
                })
                .then((res) => {
                    assert.isFalse(res);
                })
                .then(done, done);
        });

    });

    context("PreKeySignedProtocol", () => {

        it("create", (done) => {
            let identity: Identity;
            const preKeySigned = new PreKeySignedProtocol();
            Promise.resolve()
                .then(() => {
                    return createIdentity(1);
                })
                .then((res) => {
                    identity = res;
                    const preKey = res.signedPreKeys[0];

                    preKeySigned.id = identity.id;
                    preKeySigned.key = identity.signingKey.publicKey;
                    return preKeySigned.sign(identity.signingKey.privateKey);
                })
                .then(() => {
                    assert.isTrue(!!preKeySigned.id);
                    assert.isTrue(!!preKeySigned.key);
                    assert.equal(preKeySigned.signature.byteLength, 64);
                })
                .then(done, done);
        });

        it("import/export", (done) => {
            let identity: Identity;
            const preKeySigned = new PreKeySignedProtocol();
            let preKeySigned2: PreKeySignedProtocol;
            Promise.resolve()
                .then(() => {
                    return createIdentity(1);
                })
                .then((res) => {
                    identity = res;
                    const preKey = res.signedPreKeys[0];

                    preKeySigned.id = identity.id;
                    preKeySigned.key = identity.signingKey.publicKey;
                    return preKeySigned.sign(identity.signingKey.privateKey);
                })
                .then(() => {
                    return preKeySigned.exportProto();
                })
                .then((protocol) => {
                    return PreKeySignedProtocol.importProto(protocol);
                })
                .then((preKey) => {
                    preKeySigned2 = preKey;
                    isEqual(preKeySigned.signature, preKeySigned2.signature);
                    return preKeySigned2.verify(identity.signingKey.publicKey);
                })
                .then((res) => {
                    assert.isTrue(res);
                })
                .then(done, done);
        });

        it("verify", (done) => {
            let identity: Identity;
            const preKeySigned = new PreKeySignedProtocol();
            Promise.resolve()
                .then(() => {
                    return createIdentity(1);
                })
                .then((res) => {
                    identity = res;
                    const preKey = res.signedPreKeys[0];

                    preKeySigned.id = identity.id;
                    preKeySigned.key = identity.signingKey.publicKey;
                    return preKeySigned.sign(identity.signingKey.privateKey);
                })
                .then(() => {
                    return preKeySigned.verify(identity.signingKey.publicKey);
                })
                .then((res) => {
                    assert.isTrue(res);

                    const buf = new Uint8Array(preKeySigned.signature);
                    buf[3] = buf[3] + 1;
                    return preKeySigned.verify(identity.signingKey.publicKey);
                })
                .then((res) => {
                    assert.isFalse(res);
                })
                .then(done, done);
        });

    });

    context("PreKeyBundleProtocol", () => {

        context("import/export", () => {
            it("without one-time PreKey", (done) => {
                async function Test() {
                    const identity = await createIdentity(1);
                    const bundle = await createPreKeyBundle(identity);
                    const raw = await bundle.exportProto();
                    const bundle2 = await PreKeyBundleProtocol.importProto(raw);
                    assert.isTrue(bundle2.preKey.isEmpty());
                    assert.isFalse(bundle2.preKeySigned.isEmpty());
                    assert.isFalse(bundle2.identity.isEmpty());
                }
                Test().then(done, done);
            });

            it("with one-time PreKey", (done) => {
                async function Test() {
                    const identity = await createIdentity(1);
                    const bundle = await createPreKeyBundle(identity);
                    bundle.preKey.id = 1;
                    bundle.preKey.key = bundle.preKeySigned.key;
                    const raw = await bundle.exportProto();
                    const bundle2 = await PreKeyBundleProtocol.importProto(raw);
                    assert.isFalse(bundle2.preKey.isEmpty());
                    assert.isFalse(bundle2.preKeySigned.isEmpty());
                    assert.isFalse(bundle2.identity.isEmpty());
                }
                Test().then(done, done);
            });
        });

    });

});
