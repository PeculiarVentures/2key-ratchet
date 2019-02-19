import { assert } from "chai";
import { Curve, ECPublicKey } from "../src/crypto";
import "./init";

context("Crypto", () => {

    context("Curve", () => {

        it("generate 100 times", async () => {
            for (let i = 0; i < 100; i++) {
                const keys = await Curve.generateKeyPair("ECDSA");
                const raw = keys.publicKey.serialize();

                let pkey: ECPublicKey;
                pkey = await ECPublicKey.importKey(raw, "ECDSA");

                assert.isTrue(await keys.publicKey.isEqual(pkey));
            }
        });

    });

});
