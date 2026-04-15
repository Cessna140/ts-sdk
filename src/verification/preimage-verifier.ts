/**
 * Preimage (HTLC-style) condition verifier. Scans tapLeafScripts for
 * `OP_SHA256 <32B> OP_EQUAL[VERIFY]` and `OP_HASH160 <20B> OP_EQUAL[VERIFY]`
 * patterns; walks the witness stack for preimages whose hash matches.
 *
 * Bug B8 from v1 self-review: the v1 verifier iterated `finalScriptWitness`
 * as a flat `Uint8Array`, yielding 1-byte slices as "candidates". The
 * v2 module exposes {@link decodeWitnessStack} as the ONLY way to
 * extract candidates, and applies a {@link MAX_PREIMAGE_CANDIDATES} cap
 * to prevent DoS amplification.
 */

export const MAX_PREIMAGE_CANDIDATES = 64;

/**
 * Decodes a PSBT `finalScriptWitness` Uint8Array into its constituent
 * witness-stack elements (Uint8Array[]). The witness wire format is
 * `varint(count) || [varint(len) || bytes]...`.
 *
 * Callers must use this; byte-iteration over the raw `Uint8Array`
 * (v1's bug B8) is not in the module's API.
 *
 * Stub — real decoder lands in P4.
 */
export function decodeWitnessStack(
    _finalScriptWitness: Uint8Array
): readonly Uint8Array[] {
    throw new Error("decodeWitnessStack: not implemented until P4");
}

export interface PreimageVerifierInput {
    readonly path: readonly unknown[];
    readonly signal?: AbortSignal;
}

export async function verifyPreimages(
    _input: PreimageVerifierInput
): Promise<readonly unknown[]> {
    throw new Error("verifyPreimages: not implemented until P4");
}
