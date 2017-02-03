/**
 * 
 * 2key-ratchet
 * Copyright (c) 2016 Peculiar Ventures, Inc
 * Based on https://whispersystems.org/docs/specifications/doubleratchet/ and 
 * https://whispersystems.org/docs/specifications/x3dh/ by Open Whisper Systems
 * 
 */

export class Address {

    protected static readonly SPLITTER = ":";

    public name: string;
    public id: number;

    constructor(name: string, id: number) {
        this.id = id;
        this.name = name;
    }

    public toString() {
        return `${this.name}${Address.SPLITTER}${this.id}`;
    }
}
