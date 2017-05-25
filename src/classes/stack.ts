/**
 *
 * 2key-ratchet
 * Copyright (c) 2016 Peculiar Ventures, Inc
 * Based on https://whispersystems.org/docs/specifications/doubleratchet/ and
 * https://whispersystems.org/docs/specifications/x3dh/ by Open Whisper Systems
 *
 */

import { ECPublicKey } from "./crypto";
import { IJsonSerializable } from "./type";

export class Stack<T extends IJsonSerializable> implements IJsonSerializable {

    public  items: T[] = [];

    protected maxSize: number;

    get length() {
        return this.items.length;
    }

    get latest() {
        return this.items[this.length - 1];
    }

    constructor(maxSize = 20) {
        this.maxSize = maxSize;
    }

    public push(item: T) {
        if (this.length === this.maxSize) {
            this.items = this.items.slice(1); // pop first item from the items
        }
        this.items.push(item);
    }

    public async toJSON() {
        const res = [];
        for (const item of this.items) {
            res.push(await item.toJSON());
        }
        return res;
    }

    public async fromJSON(obj: T[]) {
        this.items = obj;
    }

}
