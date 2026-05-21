/* tslint:disable */
/* eslint-disable */

export function compute_blind_token(keyword: string, search_key: Uint8Array): string;

export function decrypt_symmetric(blob: Uint8Array, key: Uint8Array): Uint8Array;

export function derive_epoch_keys(master_key: Uint8Array, epoch: number): Array<any>;

export function encrypt_symmetric(plaintext: Uint8Array, key: Uint8Array): Uint8Array;

export function generate_dek(): Uint8Array;

export function generate_identity(): Array<any>;

export function master_key_to_mnemonic(master_key: Uint8Array): string;

export function mnemonic_to_master_key(phrase: string): Uint8Array;

export function open_envelope(blob: Uint8Array, privkey: Uint8Array): Uint8Array;

export function reconstructSecret(shares_json: string, threshold: number): Uint8Array;

export function seal_to_pubkey(plaintext: Uint8Array, recipient_pubkey: Uint8Array): Uint8Array;

export function sign(privkey: Uint8Array, data: Uint8Array): Uint8Array;

export function splitSecret(secret: Uint8Array, threshold: number, total_shares: number): any;

export function verify(pubkey: Uint8Array, signature: Uint8Array, data: Uint8Array): boolean;
