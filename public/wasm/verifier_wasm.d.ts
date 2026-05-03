/* tslint:disable */
/* eslint-disable */

/**
 * Verify a file given its bytes plus a separately-supplied proof bundle JSON.
 *
 * Use this when the win tag arrives separately from the file (legacy
 * `.proof.json` sidecar, URL-fetched proof bundle, etc).
 */
export function recognize_bundle(proof_json: string, file_bytes: Uint8Array): any;

/**
 * Verify a `.win` container in one call.
 *
 * Returns a `Reading` whose `status` is one of "Verified", "Tampered",
 * "Invalid". Throws only if serialization itself fails — malformed
 * containers produce an Invalid reading, not an exception.
 */
export function recognize_win(win_bytes: Uint8Array): any;

/**
 * Seal `file_bytes` into a `.win` container in the browser.
 *
 * Generates fresh creator / time-authority / policy-evaluator keypairs on
 * each call, signs the proof bundle, packs it into a `.win`, and re-runs
 * the verifier on the produced bytes. The returned `verification_status`
 * is whatever the verifier said — the UI must reflect that literally.
 *
 * `filename` is sanitized by `win_format::pack`; path separators and
 * other unsafe characters are stripped.
 */
export function seal_file(filename: string, file_bytes: Uint8Array): any;

export type InitInput = RequestInfo | URL | Response | BufferSource | WebAssembly.Module;

export interface InitOutput {
    readonly memory: WebAssembly.Memory;
    readonly recognize_bundle: (a: number, b: number, c: number, d: number, e: number) => void;
    readonly recognize_win: (a: number, b: number, c: number) => void;
    readonly seal_file: (a: number, b: number, c: number, d: number, e: number) => void;
    readonly __wbindgen_export: (a: number, b: number) => number;
    readonly __wbindgen_export2: (a: number, b: number, c: number, d: number) => number;
    readonly __wbindgen_export3: (a: number) => void;
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
