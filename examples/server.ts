import * as dgram from "dgram";
import { EventEmitter } from "events";
import { AddressInfo } from "net";
import { Convert } from "pvtsutils";
import { AsymmetricRatchet, Identity, MessageSignedProtocol } from "../index";
import { IdentityProtocol, PreKeyBundleProtocol, PreKeyMessageProtocol } from "../index";
import { ADDRESS, CLIENT_PORT, SERVER_BUNDLE_PORT, SERVER_PORT } from "./const";

export class Server extends EventEmitter {

    public static async create(id: number) {
        const server = new Server();

        const identity = await Identity.create(id, 1);
        server.identity = identity;
        const preKey = identity.signedPreKeys[0];
        // bundle
        server.bundle = new PreKeyBundleProtocol();
        server.bundle.registrationId = id;
        server.bundle.identity = await IdentityProtocol.fill(identity);
        server.bundle.preKeySigned.id = 1;
        server.bundle.preKeySigned.key = preKey.publicKey;
        await server.bundle.preKeySigned.sign(identity.signingKey.privateKey);

        server.messenger = dgram.createSocket("udp4");
        server.info = dgram.createSocket("udp4");

        server.info
            .on("listening", () => {
                server.emit("listening", server.info.address());
            })
            .on("error", (err) => {
                server.emit("error", err);
            })
            .on("message", (data, info) => {
                server.onInfo(info);
            });
        server.info.bind(SERVER_BUNDLE_PORT, ADDRESS);

        server.messenger
            .on("listening", () => {
                server.emit("listening", server.messenger.address());
            })
            .on("error", (err) => {
                server.emit("error", err);
            })
            .on("message", (data, info) => {
                const buf = new Uint8Array(data).buffer as ArrayBuffer;
                server.onMessage(buf);
            });
        server.messenger.bind(SERVER_PORT, ADDRESS);
        return server;
    }

    public identity: Identity;
    public bundle: PreKeyBundleProtocol;
    public cipher: AsymmetricRatchet;
    public messenger: dgram.Socket;
    public info: dgram.Socket;

    public on(event: string, listener: Function): this;
    public on(event: "close", listener: () => void): this;
    public on(event: "error", listener: (err: Error) => void): this;
    public on(event: "message", listener: (text: string) => void): this;
    public on(event: "listening", listener: (address: AddressInfo) => void): this;
    public on(event: string, listener: (...args: any[]) => void) {
        return super.on(event, listener);
    }

    public once(event: string, listener: Function): this;
    public once(event: "close", listener: () => void): this;
    public once(event: "error", listener: (err: Error) => void): this;
    public once(event: "message", listener: (text: string) => void): this;
    public once(event: "listening", listener: (address: AddressInfo) => void): this;
    public once(event: string, listener: (...args: any[]) => void) {
        return super.once(event, listener);
    }

    public async send(text: string) {
        const protocol = await this.cipher.encrypt(Convert.FromUtf8String(text));
        const buf = await protocol.exportProto();
        this.messenger.send(Buffer.from(buf), CLIENT_PORT, ADDRESS);
    }

    protected async onMessage(data: ArrayBuffer) {
        let message: MessageSignedProtocol;
        if (this.cipher) {
            message = await MessageSignedProtocol.importProto(data);
        } else {
            let preKeyMessage: PreKeyMessageProtocol;
            try {
                preKeyMessage = await PreKeyMessageProtocol.importProto(data);
            } catch (err) {
                this.emit("error", new Error("Incoming message is not PreKeyMessage"));
                return;
            }
            message = preKeyMessage.signedMessage;
            this.cipher = await AsymmetricRatchet.create(this.identity, preKeyMessage);
        }

        const text = await this.cipher.decrypt(message);
        this.emit("message", Convert.ToUtf8String(text));
    }

    protected async onInfo(info: dgram.RemoteInfo) {
        const bundle = await this.bundle.exportProto();
        this.info.send(Buffer.from(bundle), info.port, info.address);
    }

}
