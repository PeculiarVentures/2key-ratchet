/**
 *
 * 2key-ratchet
 * Copyright (c) 2016 Peculiar Ventures, Inc
 * Based on https://whispersystems.org/docs/specifications/doubleratchet/ and
 * https://whispersystems.org/docs/specifications/x3dh/ by Open Whisper Systems
 *
 */

import { Identity, ISession } from "./type";

export class AssocStorage<T> {
    protected items: { [key: string]: T } = {};

    public get length() {
        return Object.keys(this.items).length;
    }

    public save(key: string, value: T) {
        this.items[key] = value;
    }

    public load(key: string) {
        return this.items[key];
    }

    public remove(key: string) {
        delete this.items[key];
    }

    public clear() {
        this.items = {};
    }
}
