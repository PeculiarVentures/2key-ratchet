/**
 * 
 * 2key-ratchet
 * Copyright (c) 2016 Peculiar Ventures, Inc
 * Based on https://whispersystems.org/docs/specifications/doubleratchet/ and 
 * https://whispersystems.org/docs/specifications/x3dh/ by Open Whisper Systems
 * 
 */

import { ECPublicKey } from "./crypto";

export class Stack<T> {
    protected items: T[] = [];
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

}
