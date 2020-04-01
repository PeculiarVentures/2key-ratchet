// tslint:disable: no-console

import { Crypto } from "@peculiar/webcrypto";
import { Convert } from "pvtsutils";
import * as DKeyRatchet from "..";

async function main() {
    const crypto = new Crypto();
    DKeyRatchet.setEngine("@peculiar/webcrypto", crypto);

    // Create Alice's identity
    const AliceID = await DKeyRatchet.Identity.create(16453, 1);

    // Create PreKeyBundle
    const AlicePreKeyBundle = new DKeyRatchet.PreKeyBundleProtocol();
    await AlicePreKeyBundle.identity.fill(AliceID);
    AlicePreKeyBundle.registrationId = AliceID.id;
    // Add info about signed PreKey
    const preKey = AliceID.signedPreKeys[0];
    AlicePreKeyBundle.preKeySigned.id = 0;
    AlicePreKeyBundle.preKeySigned.key = preKey.publicKey;
    await AlicePreKeyBundle.preKeySigned.sign(AliceID.signingKey.privateKey);
    // Convert proto to bytes
    const AlicePreKeyBundleProto = await AlicePreKeyBundle.exportProto();
    console.log("Alice's bundle: ", Convert.ToHex(AlicePreKeyBundleProto));

    // Create Bob's identity
    const BobID = await DKeyRatchet.Identity.create(0, 1);

    // Parse Alice's bundle
    const bundle = await DKeyRatchet.PreKeyBundleProtocol.importProto(AlicePreKeyBundleProto);
    // Create Bob's cipher
    const BobCipher = await DKeyRatchet.AsymmetricRatchet.create(BobID, bundle);
    // Encrypt message for Alice
    const BobMessageProto = await BobCipher.encrypt(Convert.FromUtf8String("Hello Alice!!!"));
    // convert message to bytes array
    const BobMessage = await BobMessageProto.exportProto();
    console.log("Bob's encrypted message:", Convert.ToHex(BobMessage));

    // Decrypt message by Alice
    // Note: First message from Bob must be PreKeyMessage
    // parse Bob's message
    const proto = await DKeyRatchet.PreKeyMessageProtocol.importProto(BobMessage);
    // Creat Alice's cipher for Bob's message
    const AliceCipher = await DKeyRatchet.AsymmetricRatchet.create(AliceID, proto);
    // Decrypt message
    const bytes = await AliceCipher.decrypt(proto.signedMessage);
    console.log("Bob's decrypted message:", Convert.ToUtf8String(bytes));
}

main().catch((e) => console.error(e));
