import { Identity } from "../src/data";
import { PreKeyBundleProtocol } from "../src/protocol";

export async function createIdentity(id: number) {
    const identity = await Identity.create(id, 1);
    return identity;
}

export async function createPreKeyBundle(identity: Identity) {
    const bundle = new PreKeyBundleProtocol();
    await bundle.identity.fill(identity);
    const buf = new Uint8Array(bundle.identity.signature);
    // buf[0] = buf[0] + 1;
    // buf.forEach((b, i, a) => a[i] = 0);

    const preKeyId = 0;
    const preKey = identity.signedPreKeys[preKeyId];
    bundle.preKeySigned.id = preKeyId;
    bundle.preKeySigned.key = preKey.publicKey;
    await bundle.preKeySigned.sign(identity.signingKey.privateKey);

    bundle.registrationId = 1;

    // const raw = await bundle.exportProtocol();
    // console.log(Convert.ToHex(raw));

    return bundle;
}
