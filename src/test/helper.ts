import { Identity, PreKey } from "../classes/data";
import { PreKeyBundleProtocol } from "../classes/protocol";

export async function createIdentity(id: number) {
    const identity = await Identity.create(id);
    const preKey = await PreKey.create(1);
    identity.signedPreKeys.save(preKey.id.toString(), preKey);
    return identity;
}

export async function createPreKeyBundle(identity: Identity) {
    const bundle = new PreKeyBundleProtocol();
    await bundle.identity.fill(identity);
    const buf = new Uint8Array(bundle.identity.signature);
    // buf[0] = buf[0] + 1;
    // buf.forEach((b, i, a) => a[i] = 0);

    const preKey = identity.signedPreKeys.load("1");
    bundle.preKeySigned.id = preKey.id;
    bundle.preKeySigned.key = preKey.key.publicKey;
    await bundle.preKeySigned.sign(identity.signingKey.privateKey);

    bundle.registrationId = 1;

    // const raw = await bundle.exportProtocol();
    // console.log(Convert.ToHex(raw));

    return bundle;
}
