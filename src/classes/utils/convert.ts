/**
 * 
 * 2key-ratchet
 * Copyright (c) 2016 Peculiar Ventures, Inc
 * Based on https://whispersystems.org/docs/specifications/doubleratchet/ and 
 * https://whispersystems.org/docs/specifications/x3dh/ by Open Whisper Systems
 * 
 */

export type BufferEncoding = "utf8" | "binary" | "base64" | "base64url" | "hex" | string;

declare const unescape: (value: string) => string;
declare const escape: (value: string) => string;

function PrepareBuffer(buffer: BufferSource) {
    if (typeof Buffer !== "undefined") {
        return new Uint8Array(buffer as any);
    } else {
        return new Uint8Array(buffer instanceof ArrayBuffer ? buffer : buffer.buffer);
    }
}

export class Convert {

    public static ToString(buffer: BufferSource, enc: BufferEncoding = "utf8") {
        const buf = PrepareBuffer(buffer);
        switch (enc.toLowerCase()) {
            case "utf8":
                return this.ToUtf8String(buf);
            case "binary":
                return this.ToBinary(buf);
            case "hex":
                return this.ToHex(buf);
            case "base64":
                return this.ToBase64(buf);
            case "base64url":
                return this.ToBase64Url(buf);
            default:
                throw new Error(`Unknown type of encoding '${enc}'`);
        }
    }
    public static FromString(str: string, enc: BufferEncoding = "utf8") {
        switch (enc.toLowerCase()) {
            case "utf8":
                return this.FromUtf8String(str);
            case "binary":
                return this.FromBinary(str);
            case "hex":
                return this.FromHex(str);
            case "base64":
                return this.FromBase64(str);
            case "base64url":
                return this.FromBase64Url(str);
            default:
                throw new Error(`Unknown type of encoding '${enc}'`);
        }
    }

    public static ToBase64(buffer: BufferSource): string {
        const buf = PrepareBuffer(buffer);
        if (typeof btoa !== "undefined") {
            const binary = this.ToString(buf, "binary");
            return btoa(binary);
        } else {
            return new Buffer(buf).toString("base64");
        }
    }

    public static FromBase64(base64Text: string) {
        base64Text = base64Text.replace(/\n/g, "").replace(/\r/g, "").replace(/\t/g, "").replace(/\s/g, "");
        if (typeof atob !== "undefined") {
            return this.FromBinary(atob(base64Text));
        } else {
            return new Uint8Array(new Buffer(base64Text, "base64")).buffer;
        }
    }

    public static FromBase64Url(base64url: string) {
        return this.FromBase64(this.Base64Padding(base64url.replace(/\-/g, "+").replace(/\_/g, "/")));
    }

    public static ToBase64Url(data: BufferSource): string {
        return this.ToBase64(data).replace(/\+/g, "-").replace(/\//g, "_").replace(/\=/g, "");
    }

    public static FromUtf8String(text: string) {
        const s = unescape(encodeURIComponent(text));
        const uintArray = new Uint8Array(s.length);
        for (let i = 0; i < s.length; i++) {
            uintArray[i] = s.charCodeAt(i);
        }
        return uintArray.buffer;
    }

    public static ToUtf8String(buffer: BufferSource): string {
        const buf = PrepareBuffer(buffer);
        const encodedString = String.fromCharCode.apply(null, buf);
        const decodedString = decodeURIComponent(escape(encodedString));
        return decodedString;
    }

    public static FromBinary(text: string) {
        const stringLength = text.length;
        const resultView = new Uint8Array(stringLength);
        for (let i = 0; i < stringLength; i++) {
            resultView[i] = text.charCodeAt(i);
        }
        return resultView.buffer;
    }
    public static ToBinary(buffer: BufferSource): string {
        const buf = PrepareBuffer(buffer);
        let resultString = "";
        const len = buf.length;
        for (let i = 0; i < len; i++) {
            resultString = resultString + String.fromCharCode(buf[i]);
        }
        return resultString;
    }

    /**
     * Converts buffer to HEX string
     * @param  {BufferSource} buffer Incoming buffer
     * @returns string
     */
    public static ToHex(buffer: BufferSource): string {
        const buf = PrepareBuffer(buffer);
        const splitter = "";
        const res: string[] = [];
        const len = buf.length;
        for (let i = 0; i < len; i++) {
            const char = buf[i].toString(16);
            res.push(char.length === 1 ? "0" + char : char);
        }
        return res.join(splitter);
    }

    /**
     * Converts HEX string to buffer
     * 
     * @static
     * @param {string} hexString
     * @returns {Uint8Array}
     * 
     * @memberOf Convert
     */
    public static FromHex(hexString: string) {
        const res = new Uint8Array(hexString.length / 2);
        for (let i = 0; i < hexString.length; i = i + 2) {
            const c = hexString.slice(i, i + 2);
            res[i / 2] = parseInt(c, 16);
        }
        return res.buffer;
    }

    protected static Base64Padding(base64: string): string {
        const padCount = 4 - (base64.length % 4);
        if (padCount < 4) {
            for (let i = 0; i < padCount; i++) {
                base64 += "=";
            }
        }
        return base64;
    }

}
