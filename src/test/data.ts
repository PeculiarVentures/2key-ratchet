import { assert } from "chai";
import { Convert, isEqual } from "pvtsutils";
import { Identity, RemoteIdentity } from "../classes/data";
import { IdentityProtocol } from "../classes/protocol";
import { createIdentity, createPreKeyBundle } from "./helper";

context("Data", () => {

    context("Identity", () => {

        it("toJSON/fromJSON", (done) => {
            Promise.resolve()
                .then(() => {
                    return Identity.create(1, 3, 5);
                })
                .then((identity) => {
                    return identity.toJSON()
                        .then((json) => {
                            return Identity.fromJSON(json);
                        })
                        .then((identity2) => {
                            assert.equal(identity.createdAt.toString(), identity2.createdAt.toString());
                            assert.equal(identity.signedPreKeys.length, identity2.signedPreKeys.length);
                        });
                })
                .then(done, done);
        });

    });

    context("RemoteIdentity", () => {

        it("fill", (done) => {
            Promise.resolve()
                .then(() => {
                    return createIdentity(1);
                })
                .then((res) => {
                    return IdentityProtocol.fill(res);
                })
                .then((identity) => {
                    return RemoteIdentity.fill(identity);
                })
                .then((remote) => {
                    assert.isTrue(!!remote.createdAt);
                    assert.isTrue(!!remote.signature);
                    assert.isTrue(!!remote.signingKey);
                    assert.isTrue(!!remote.exchangeKey);
                    assert.isFalse(!!remote.id);
                })
                .then(done, done);
        });

        it("toJSON/fromJSON", (done) => {
            Promise.resolve()
                .then(() => {
                    return createIdentity(1);
                })
                .then((res) => {
                    return IdentityProtocol.fill(res);
                })
                .then((identity) => {
                    return RemoteIdentity.fill(identity);
                })
                .then((remote) => {
                    return remote.toJSON()
                        .then((json) => {
                            return RemoteIdentity.fromJSON(json);
                        })
                        .then((remote2) => {
                            assert.equal(remote.createdAt.toString(), remote2.createdAt.toString());
                            assert.equal(remote.signingKey.id, remote2.signingKey.id);
                            assert.equal(remote.exchangeKey.id, remote2.exchangeKey.id);
                            assert.isTrue(isEqual(remote.signature, remote2.signature));
                            assert.equal(remote.id, remote2.id);
                        });
                })
                .then(done, done);
        });

    });
    it("fromJSON with wrong signature", (done) => {
        Promise.resolve()
            .then(() => {
                return createIdentity(1);
            })
            .then((res) => {
                return IdentityProtocol.fill(res);
            })
            .then((identity) => {
                return RemoteIdentity.fill(identity);
            })
            .then((remote) => {
                return remote.toJSON()
                    .then((json) => {
                        const signature = new Uint8Array(json.signature);
                        signature[3] += 1; // change 1 byte in signature
                        return RemoteIdentity.fromJSON(json);
                    })
                    .then(() => {
                        throw new Error("Must be error on signature verification");
                    }, (err) => {
                        assert.equal(!!err, true);
                    });
            })
            .then(done, done);
    });

});
