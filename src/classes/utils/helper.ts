/**
 * 
 * 2key-ratchet
 * Copyright (c) 2016 Peculiar Ventures, Inc
 * Based on https://whispersystems.org/docs/specifications/doubleratchet/ and 
 * https://whispersystems.org/docs/specifications/x3dh/ by Open Whisper Systems
 * 
 */

export function assign(target: any, ...sources: any[]) {
    const res = arguments[0];
    for (let i = 1; i < arguments.length; i++) {
        const obj = arguments[i];
        for (const prop in obj) {
            res[prop] = obj[prop];
        }
    }
    return res;
}

export function combine(...buf: ArrayBuffer[]) {
    const totalByteLength = buf.map((item) => item.byteLength).reduce((prev, cur) => prev + cur);
    const res = new Uint8Array(totalByteLength);
    let currentPos = 0;
    buf.map((item) => new Uint8Array(item)).forEach((arr) => {
        for (let i = 0; i < arr.length; i++) {
            res[currentPos++] = arr[i];
        }
    });
    return res.buffer;
}

export function isEqual(bytes1: ArrayBuffer, bytes2: ArrayBuffer) {
    if (!(bytes1 && bytes2)) { return false; }
    if (bytes1.byteLength !== bytes2.byteLength) { return false; }

    const b1 = new Uint8Array(bytes1);
    const b2 = new Uint8Array(bytes2);
    for (let i = 0; i < bytes1.byteLength; i++) {
        if (b1[i] !== b2[i]) { return false; }
    }
    return true;
}
