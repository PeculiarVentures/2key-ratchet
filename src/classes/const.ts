/**
 *
 * 2key-ratchet
 * Copyright (c) 2016 Peculiar Ventures, Inc
 * Based on https://whispersystems.org/docs/specifications/doubleratchet/ and
 * https://whispersystems.org/docs/specifications/x3dh/ by Open Whisper Systems
 *
 */

import { Convert } from "pvtsutils";
export const SIGN_ALGORITHM_NAME = "ECDSA";
export const DH_ALGORITHM_NAME = "ECDH";
export const SECRET_KEY_NAME = "AES-CBC";
export const HASH_NAME = "SHA-256";
export const HMAC_NAME = "HMAC";

export const MAX_RATCHET_STACK_SIZE = 20;

export const INFO_TEXT = Convert.FromBinary("InfoText");
export const INFO_RATCHET = Convert.FromBinary("InfoRatchet");
export const INFO_MESSAGE_KEYS = Convert.FromBinary("InfoMessageKeys");
