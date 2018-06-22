/**
 * 
 * Simple 2key-ratchet example
 * Creates identity Alice and Bob.
 * Bob creates encrypted message for Alice. He uses Alice's PreKeyBundle message.
 * Alice decrypts message from Bob
 * 
 */

const DKeyRatchet = require("2key-ratchet");
const { Convert } = require("pvtsutils");

let AliceID, BobID;
let AlicePreKeyBundleProto;
let BobMessage;
Promise.resolve()
    .then(() => {
        // Create Alice's identity
        return DKeyRatchet.Identity.create(16453, 1, 1)
            .then((identity) => {
                AliceID = identity;

                // Create PreKeyBundle
                let AlicePreKeyBundle = new DKeyRatchet.PreKeyBundleProtocol();
                AlicePreKeyBundle.identity.fill(AliceID)
                    .then(() => {
                        AlicePreKeyBundle.registrationId = AliceID.id;
                        // Add info about signed PreKey
                        const preKey = AliceID.signedPreKeys[0];
                        AlicePreKeyBundle.preKeySigned.id = 0;
                        AlicePreKeyBundle.preKeySigned.key = preKey.publicKey;
                        return AlicePreKeyBundle.preKeySigned.sign(AliceID.signingKey.privateKey)
                            .then(() => {
                                // Convert proto to bytes
                                return AlicePreKeyBundle.exportProto();
                            })
                            .then((bytes) => {
                                AlicePreKeyBundleProto = bytes;
                                console.log("Alice's bundle: ", AlicePreKeyBundleProto);
                            });
                    })
            })
            .then(() => {
                // Create Bob's identity
                return DKeyRatchet.Identity.create(0, 1, 1)
                    .then((identity) => {
                        BobID = identity;

                        // Parse Alice's bundle
                        return DKeyRatchet.PreKeyBundleProtocol.importProto(AlicePreKeyBundleProto)
                            .then((bundle) => {
                                // Create Bob's cipher
                                return DKeyRatchet.AsymmetricRatchet.create(BobID, bundle);
                            })
                    })
                    .then((BobCipher) => {
                        // Encrypt message for Alice
                        return BobCipher.encrypt(Convert.FromUtf8String("Hello Alice!!!"));
                    })
                    .then((proto) => {
                        // convert message to bytes array
                        return proto.exportProto()
                    })
                    .then((bytes) => {
                        BobMessage = bytes;
                        console.log("Bob's encrypted message:", BobMessage);
                    })
            })
            .then(() => {
                // Decrypt message by Alice

                // Note: First message from Bob must be PreKeyMessage
                // parse Bob's message
                return DKeyRatchet.PreKeyMessageProtocol.importProto(BobMessage)
                    .then((proto) => {
                        // Creat Alice's cipher for Bob's message
                        return DKeyRatchet.AsymmetricRatchet.create(AliceID, proto)
                            .then((AliceCipher) => {
                                // Decrypt message
                                return AliceCipher.decrypt(proto.signedMessage);
                            })
                            .then((bytes) => {
                                console.log("Bob's decrypted message:", Convert.ToUtf8String(bytes));
                            })
                    });
            })

    })
    .catch((e) => {
        console.error(e);
    })