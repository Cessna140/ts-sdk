/**
 * Shared helpers for the verification module.
 *
 * These small BIP 341 / byte-comparison utilities are used by multiple
 * verifiers. Centralising them avoids duplication and ensures a single
 * place to fix bugs.
 */

import { schnorr } from "@noble/curves/secp256k1.js";
import { tapLeafHash } from "@scure/btc-signer/payment.js";
import { equalBytes } from "@scure/btc-signer/utils.js";
import { MalformedChainError } from "./errors";

export const bytesEqual = equalBytes;

export function compareBytes(a: Uint8Array, b: Uint8Array): number {
    const n = Math.min(a.length, b.length);
    for (let i = 0; i < n; i++) {
        if (a[i] !== b[i]) return a[i] - b[i];
    }
    return a.length - b.length;
}

export function tapBranchHash(a: Uint8Array, b: Uint8Array): Uint8Array {
    const [lo, hi] = compareBytes(a, b) <= 0 ? [a, b] : [b, a];
    return new Uint8Array(schnorr.utils.taggedHash("TapBranch", lo, hi));
}

/**
 * Compute the BIP 341 taptree merkle root from decoded leaves
 * (BIP 371 `{depth, version, script}[]` format). Returns `null` for
 * empty or malformed trees.
 */
export function tapTreeMerkleRoot(
    leaves: ReadonlyArray<{
        depth: number;
        version: number;
        script: Uint8Array;
    }>
): Uint8Array | null {
    if (leaves.length === 0) return null;
    const stack: Array<{ depth: number; hash: Uint8Array }> = [];
    for (const leaf of leaves) {
        let hash = tapLeafHash(leaf.script, leaf.version);
        let depth = leaf.depth;
        while (stack.length > 0 && stack[stack.length - 1].depth === depth) {
            const sibling = stack.pop()!;
            hash = tapBranchHash(sibling.hash, hash);
            depth--;
        }
        stack.push({ depth, hash });
    }
    return stack.length === 1 ? stack[0].hash : null;
}

/**
 * Extract the 32-byte x-only pubkey from a P2TR scriptPubKey
 * (`OP_1 0x20 <32B>`). Returns `null` on non-P2TR shape.
 */
export function p2trXOnlyKey(script: Uint8Array): Uint8Array | null {
    if (script.length !== 34 || script[0] !== 0x51 || script[1] !== 0x20) {
        return null;
    }
    return script.subarray(2);
}

export function throwIfAborted(signal?: AbortSignal, txid?: string): void {
    if (signal?.aborted) {
        throw new MalformedChainError({
            kind: "UNSUPPORTED",
            code: "aborted",
            message: `Verification aborted${txid ? ` (near tx ${txid})` : ""}`,
        });
    }
}

/** Cap for VtxoTaprootTree blob size before decoding — DoS guard. */
export const MAX_TAPTREE_BLOB_BYTES = 100_000;
