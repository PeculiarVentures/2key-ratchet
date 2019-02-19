import { assert } from "chai";
import { isEqual } from "pvtsutils";
import { Identity, RemoteIdentity } from "../src/data";
import { IdentityProtocol } from "../src/protocol";
import { createIdentity } from "./helper";
import "./init";

context("Data", () => {

    context("Identity", () => {

        it("toJSON/fromJSON", async () => {
            const identity = await Identity.create(1, 3, 5);
            const json = await identity.toJSON();
            const identity2 = await Identity.fromJSON(json);
            assert.equal(identity.createdAt.toString(), identity2.createdAt.toString());
            assert.equal(identity.signedPreKeys.length, identity2.signedPreKeys.length);
        });

    });

    context("RemoteIdentity", () => {

        it("fill", async () => {
            const res = await createIdentity(1);
            const identity = await IdentityProtocol.fill(res);
            const remote = await RemoteIdentity.fill(identity);

            assert.isTrue(!!remote.createdAt);
            assert.isTrue(!!remote.signature);
            assert.isTrue(!!remote.signingKey);
            assert.isTrue(!!remote.exchangeKey);
            assert.isFalse(!!remote.id);
        });

        it("toJSON/fromJSON", async () => {
            const res = await createIdentity(1);
            const identity = await IdentityProtocol.fill(res);
            const remote = await RemoteIdentity.fill(identity);
            const json = await remote.toJSON();
            const remote2 = await RemoteIdentity.fromJSON(json);

            assert.equal(remote.createdAt.toString(), remote2.createdAt.toString());
            assert.equal(remote.signingKey.id, remote2.signingKey.id);
            assert.equal(remote.exchangeKey.id, remote2.exchangeKey.id);
            assert.isTrue(isEqual(remote.signature, remote2.signature));
            assert.equal(remote.id, remote2.id);
        });

    });

    it("fromJSON with wrong signature", async () => {
        const res = await createIdentity(1);
        const identity = await IdentityProtocol.fill(res);
        const remote = await RemoteIdentity.fill(identity);
        const json = await remote.toJSON();
        const signature = new Uint8Array(json.signature);
        signature[3] += 1; // change 1 byte in signature
        await RemoteIdentity.fromJSON(json)
            .then(() => {
                throw new Error("Must be error on signature verification");
            }, (err: Error) => {
                assert.equal(!!err, true);
            });
    });

});
