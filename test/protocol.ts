import { assert } from "chai";
import { isEqual } from "pvtsutils";
import { IdentityProtocol, PreKeyBundleProtocol } from "../src/protocol";
import { PreKeySignedProtocol } from "../src/protocol/prekey_signed";
import { createIdentity, createPreKeyBundle } from "./helper";
import "./init";

context("Protocol", () => {

    context("IdentityProtocol", () => {

        it("create", async () => {
            const res = await createIdentity(1);
            const identity = await IdentityProtocol.fill(res);

            assert.isTrue(!!identity.signingKey);
            assert.isTrue(!!identity.exchangeKey);
            assert.equal(identity.signature.byteLength, 64);
        });

        it("import/export", async () => {
            const identity = await createIdentity(1);
            const identityProto = await IdentityProtocol.fill(identity);
            const identityBuf = await identityProto.exportProto();
            const identityProto2 = await IdentityProtocol.importProto(identityBuf);
            assert.equal(identityProto.signingKey.id, identityProto2.signingKey.id);
            assert.equal(identityProto.exchangeKey.id, identityProto2.exchangeKey.id);
            assert.isTrue(isEqual(identityProto.signature, identityProto2.signature));
        });

        it("verify", async () => {
            const identity = await createIdentity(1);
            const identityProto = await IdentityProtocol.fill(identity);

            const res3 = await identityProto.verify();
            assert.isTrue(res3);

            // break signature
            const buf = new Uint8Array(identityProto.signature);
            buf[3] = buf[3] + 1;
            const res4 = await identityProto.verify();
            assert.isFalse(res4);
        });

    });

    context("PreKeySignedProtocol", () => {

        it("create", async () => {
            const preKeySigned = new PreKeySignedProtocol();
            const identity = await createIdentity(1);

            preKeySigned.id = identity.id;
            preKeySigned.key = identity.signingKey.publicKey;
            await preKeySigned.sign(identity.signingKey.privateKey);

            assert.isTrue(!!preKeySigned.id);
            assert.isTrue(!!preKeySigned.key);
            assert.equal(preKeySigned.signature.byteLength, 64);
        });

        it("import/export", async () => {
            const preKeySigned = new PreKeySignedProtocol();
            let preKeySigned2: PreKeySignedProtocol;
            const identity = await createIdentity(1);
            preKeySigned.id = identity.id;
            preKeySigned.key = identity.signingKey.publicKey;
            await preKeySigned.sign(identity.signingKey.privateKey);
            const protocol = await preKeySigned.exportProto();
            const preKey = await PreKeySignedProtocol.importProto(protocol);

            preKeySigned2 = preKey;
            isEqual(preKeySigned.signature, preKeySigned2.signature);
            const ok = await preKeySigned2.verify(identity.signingKey.publicKey);
            assert.isTrue(ok);
        });

        it("verify", async () => {
            const preKeySigned = new PreKeySignedProtocol();
            const identity = await createIdentity(1);
            preKeySigned.id = identity.id;
            preKeySigned.key = identity.signingKey.publicKey;
            await preKeySigned.sign(identity.signingKey.privateKey);
            const ok = await preKeySigned.verify(identity.signingKey.publicKey);
            assert.isTrue(ok);

            const buf = new Uint8Array(preKeySigned.signature);
            buf[3] = buf[3] + 1;
            const ok2 = await preKeySigned.verify(identity.signingKey.publicKey);
            assert.isFalse(ok2);
        });

    });

    context("PreKeyBundleProtocol", () => {

        context("import/export", () => {
            it("without one-time PreKey", async () => {
                const identity = await createIdentity(1);
                const bundle = await createPreKeyBundle(identity);
                const raw = await bundle.exportProto();
                const bundle2 = await PreKeyBundleProtocol.importProto(raw);
                assert.isTrue(bundle2.preKey.isEmpty());
                assert.isFalse(bundle2.preKeySigned.isEmpty());
                assert.isFalse(bundle2.identity.isEmpty());
            });

            it("with one-time PreKey", async () => {
                const identity = await createIdentity(1);
                const bundle = await createPreKeyBundle(identity);
                bundle.preKey.id = 1;
                bundle.preKey.key = bundle.preKeySigned.key;
                const raw = await bundle.exportProto();
                const bundle2 = await PreKeyBundleProtocol.importProto(raw);
                assert.isFalse(bundle2.preKey.isEmpty());
                assert.isFalse(bundle2.preKeySigned.isEmpty());
                assert.isFalse(bundle2.identity.isEmpty());
            });
        });

    });

});
