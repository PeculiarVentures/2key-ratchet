/**
 * 
 * 2key-ratchet
 * Copyright (c) 2016 Peculiar Ventures, Inc
 * Based on https://whispersystems.org/docs/specifications/doubleratchet/ and 
 * https://whispersystems.org/docs/specifications/x3dh/ by Open Whisper Systems
 * 
 */

import { Type } from "protobufjs";
import { IConverter } from "./converter";
import { ProtocolObject } from "./protocol_object";

export interface IProtobufSerializable {
    importProtocol(raw: ArrayBuffer): PromiseLike<void>;
    exportProtocol(): PromiseLike<ArrayBuffer | undefined>;
}

export interface IProtobufScheme {
    localName?: string;
    items?: { [key: string]: IProtobufSchemeItem<any> };
    target?: any;
    protobuf?: Type;
}

export interface IProtobufSchemeItem<T> {
    name?: string;
    id: number;
    required?: boolean;
    type?: string;
    converter?: IConverter<T>;
    defaultValue?: T;
    parser?: typeof ProtocolObject;
}

export interface IProtobufElement {
    /**
     * Name of protobuf schema element
     */
    name?: string;
}
