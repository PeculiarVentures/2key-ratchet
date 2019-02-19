import { assert } from "chai";
import { Convert, isEqual } from "pvtsutils";
import { AsymmetricRatchet } from "../src/asym_ratchet";
import { MessageSignedProtocol, PreKeyMessageProtocol } from "../src/protocol";
import { createIdentity, createPreKeyBundle } from "./helper";
import "./init";

const MESSAGE = Convert.FromUtf8String("Привет!");
const TIMES = 10;

async function createCiphers() {
    const AliceID = await createIdentity(1);
    const BobID = await createIdentity(2);
    const AlicePreKeyBundle = await createPreKeyBundle(AliceID);

    const BobRatchet = await AsymmetricRatchet.create(BobID, AlicePreKeyBundle);
    const HelloMessage = await BobRatchet.encrypt(MESSAGE) as PreKeyMessageProtocol;
    const AliceRatchet = await AsymmetricRatchet.create(AliceID, HelloMessage);
    const decrypted = await AliceRatchet.decrypt(HelloMessage.signedMessage);
    assert.isTrue(isEqual(decrypted, MESSAGE));
    return { Alice: AliceRatchet, Bob: BobRatchet };
}

async function sendMessage(fromCipher: AsymmetricRatchet, toCipher: AsymmetricRatchet) {
    const message = await fromCipher.encrypt(MESSAGE) as MessageSignedProtocol;
    assert.isTrue(isEqual(await toCipher.decrypt(message), MESSAGE));
}

async function dialog(cipher1: AsymmetricRatchet, cipher2: AsymmetricRatchet, times = TIMES) {
    for (let i = 0; i < times; i++) {
        await sendMessage(cipher1, cipher2);
        await sendMessage(cipher2, cipher1);
    }
}

context("Encryption", () => {

    it("ping pong", async () => {
        const ciphers = await createCiphers();
        await dialog(ciphers.Alice, ciphers.Bob);
    });

    it("bla bla bla", async () => {
        const ciphers = await createCiphers();

        for (let i = 0; i < TIMES; i++) {
            await sendMessage(ciphers.Alice, ciphers.Bob);
            await sendMessage(ciphers.Alice, ciphers.Bob);
            await sendMessage(ciphers.Alice, ciphers.Bob);
            await sendMessage(ciphers.Alice, ciphers.Bob);
            await sendMessage(ciphers.Alice, ciphers.Bob);
            assert.equal(ciphers.Alice.counter, i + 1);
            await sendMessage(ciphers.Bob, ciphers.Alice);
        }
    });

    it("wrong order", async () => {
        const ciphers = await createCiphers();
        const { Alice, Bob } = ciphers;

        const AliceMsg1 = await Alice.encrypt(MESSAGE) as MessageSignedProtocol; // slow message
        await dialog(Alice, Bob, 5);
        assert.isTrue(isEqual(await Bob.decrypt(AliceMsg1), MESSAGE));
        await dialog(Alice, Bob, 5);
    });

    it("too old message", async () => {
        const ciphers = await createCiphers();
        const { Alice, Bob } = ciphers;

        // Use unhandledRejection
        process.once("unhandledRejection", () => {
            // NOTE: Unhandled promise rejections are deprecated. In the future,
            // promise rejections that are not handled will terminate the Node.js
            // process with a non-zero exit code
        });

        const AliceMsg1 = await Alice.encrypt(MESSAGE) as MessageSignedProtocol; // old message
        await dialog(Alice, Bob, 25);
        try {
            await Bob.decrypt(AliceMsg1);
            throw new Error("Must be error");
        } catch (err) {
            // console.error(err.message);
        }
        await dialog(Alice, Bob, 5);
    });

});
