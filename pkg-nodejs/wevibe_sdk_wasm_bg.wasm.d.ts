/* tslint:disable */
/* eslint-disable */
export const memory: WebAssembly.Memory;
export const compute_blind_token: (a: number, b: number, c: number, d: number) => [number, number, number, number];
export const decrypt_symmetric: (a: number, b: number, c: number, d: number) => [number, number, number];
export const derive_epoch_keys: (a: number, b: number, c: number) => [number, number, number];
export const encrypt_symmetric: (a: number, b: number, c: number, d: number) => [number, number, number];
export const generate_identity: () => any;
export const master_key_to_mnemonic: (a: number, b: number) => [number, number, number, number];
export const mnemonic_to_master_key: (a: number, b: number) => [number, number, number];
export const open_envelope: (a: number, b: number, c: number, d: number) => [number, number, number];
export const reconstructSecret: (a: number, b: number, c: number) => [number, number, number, number];
export const seal_to_pubkey: (a: number, b: number, c: number, d: number) => [number, number, number];
export const sign: (a: number, b: number, c: number, d: number) => [number, number, number];
export const splitSecret: (a: number, b: number, c: number, d: number) => [number, number, number];
export const verify: (a: number, b: number, c: number, d: number, e: number, f: number) => number;
export const generate_dek: () => any;
export const __wbindgen_exn_store: (a: number) => void;
export const __externref_table_alloc: () => number;
export const __wbindgen_externrefs: WebAssembly.Table;
export const __wbindgen_malloc: (a: number, b: number) => number;
export const __wbindgen_realloc: (a: number, b: number, c: number, d: number) => number;
export const __externref_table_dealloc: (a: number) => void;
export const __wbindgen_free: (a: number, b: number, c: number) => void;
export const __wbindgen_start: () => void;
