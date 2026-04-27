/* tslint:disable */
/* eslint-disable */

/**
 * Recognize a file given its bytes plus a separately-supplied proof bundle JSON.
 *
 * Use this when the name tag arrives separately from the file (legacy
 * `.proof.json` sidecar, URL-fetched proof bundle, etc).
 */
export function recognize_bundle(proof_json: string, file_bytes: Uint8Array): any;

/**
 * Recognize a `.win` container in one call.
 *
 * Returns a `Reading` whose `status` is one of "Verified", "Tampered",
 * "Invalid", "Dying". Throws if the bytes can't even be returned as a
 * valid Reading — but this should not happen because malformed containers
 * produce an Unrecognized reading rather than an exception.
 */
export function recognize_win(win_bytes: Uint8Array): any;

export type InitInput = RequestInfo | URL | Response | BufferSource | WebAssembly.Module;

export interface InitOutput {
    readonly memory: WebAssembly.Memory;
    readonly recognize_bundle: (a: number, b: number, c: number, d: number, e: number) => void;
    readonly recognize_win: (a: number, b: number, c: number) => void;
    readonly __wbindgen_export: (a: number, b: number) => number;
    readonly __wbindgen_export2: (a: number, b: number, c: number, d: number) => number;
    readonly __wbindgen_add_to_stack_pointer: (a: number) => number;
}

export type SyncInitInput = BufferSource | WebAssembly.Module;

/**
 * Instantiates the given `module`, which can either be bytes or
 * a precompiled `WebAssembly.Module`.
 *
 * @param {{ module: SyncInitInput }} module - Passing `SyncInitInput` directly is deprecated.
 *
 * @returns {InitOutput}
 */
export function initSync(module: { module: SyncInitInput } | SyncInitInput): InitOutput;

/**
 * If `module_or_path` is {RequestInfo} or {URL}, makes a request and
 * for everything else, calls `WebAssembly.instantiate` directly.
 *
 * @param {{ module_or_path: InitInput | Promise<InitInput> }} module_or_path - Passing `InitInput` directly is deprecated.
 *
 * @returns {Promise<InitOutput>}
 */
export default function __wbg_init (module_or_path?: { module_or_path: InitInput | Promise<InitInput> } | InitInput | Promise<InitInput>): Promise<InitOutput>;
